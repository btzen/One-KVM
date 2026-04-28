//! Cryptographic primitives for IPMI 2.0 (RMCP+).
//!
//! Implements:
//! - HMAC-SHA1 / HMAC-SHA1-96 for integrity
//! - AES-CBC-128 for confidentiality
//! - Diffie-Hellman key exchange for RAKP
//! - Key derivation (K_UID, SIK, K1, K2)

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use num_bigint_dig::BigUint;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const SHA1_LEN: usize = 20;
const HMAC_SHA1_96_LEN: usize = 12;
const AES_BLOCK: usize = 16;

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_LEN] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; SHA1_LEN];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn hmac_sha1_96(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA1_96_LEN] {
    let full = hmac_sha1(key, data);
    let mut out = [0u8; HMAC_SHA1_96_LEN];
    out.copy_from_slice(&full[..HMAC_SHA1_96_LEN]);
    out
}

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut prev = [0u8; AES_BLOCK];
    prev.copy_from_slice(iv);
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    for chunk in plaintext.chunks(AES_BLOCK) {
        let mut xored = [0u8; AES_BLOCK];
        for (i, &b) in chunk.iter().enumerate() {
            xored[i] = b ^ prev[i];
        }
        let mut block = GenericArray::clone_from_slice(&xored);
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(&block);
        ciphertext.extend_from_slice(&block);
    }

    ciphertext
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let decipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut prev = [0u8; AES_BLOCK];
    prev.copy_from_slice(iv);
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(AES_BLOCK) {
        let mut block = GenericArray::clone_from_slice(chunk);
        decipher.decrypt_block(&mut block);
        for i in 0..AES_BLOCK {
            plaintext.push(block[i] ^ prev[i]);
        }
        prev.copy_from_slice(chunk);
    }

    plaintext
}

pub fn ipmi2_encrypt(key: &[u8], msg_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let enc_pad_len = (AES_BLOCK - ((msg_bytes.len() + 2) % AES_BLOCK)) % AES_BLOCK;
    let mut plaintext = Vec::with_capacity(msg_bytes.len() + enc_pad_len + 2);
    plaintext.extend_from_slice(msg_bytes);
    plaintext.extend(std::iter::repeat(0u8).take(enc_pad_len));
    plaintext.push(enc_pad_len as u8);
    plaintext.push(0x07);

    let mut iv = [0u8; AES_BLOCK];
    for b in iv.iter_mut() {
        *b = rand::random::<u8>();
    }

    let ciphertext = aes_cbc_encrypt(key, &iv, &plaintext);
    (iv.to_vec(), ciphertext)
}

pub fn ipmi2_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let plaintext = aes_cbc_decrypt(key, iv, ciphertext);
    if plaintext.len() < 2 {
        return None;
    }
    let next_header = *plaintext.last()?;
    if next_header != 0x07 {
        return None;
    }
    let enc_pad_len = plaintext[plaintext.len() - 2] as usize;
    if plaintext.len() < enc_pad_len + 2 {
        return None;
    }
    let msg_len = plaintext.len() - enc_pad_len - 2;
    Some(plaintext[..msg_len].to_vec())
}

pub fn dh_generate_keypair(prime: &[u8], generator: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let p = BigUint::from_bytes_be(prime);
    let g = BigUint::from_bytes_be(generator);

    let mut private_bytes = vec![0u8; prime.len()];
    for b in private_bytes.iter_mut() {
        *b = rand::random::<u8>();
    }
    private_bytes[0] |= 0x80;

    let x = BigUint::from_bytes_be(&private_bytes);
    let public = g.modpow(&x, &p);

    (private_bytes, public.to_bytes_be())
}

pub fn dh_shared_secret(prime: &[u8], peer_public: &[u8], my_private: &[u8]) -> Vec<u8> {
    let p = BigUint::from_bytes_be(prime);
    let y = BigUint::from_bytes_be(peer_public);
    let x = BigUint::from_bytes_be(my_private);

    let shared = y.modpow(&x, &p);
    shared.to_bytes_be()
}

pub fn compute_k_uid(password: &[u8], username: &[u8]) -> [u8; SHA1_LEN] {
    let mut pwd = [0u8; 20];
    let plen = password.len().min(20);
    pwd[..plen].copy_from_slice(&password[..plen]);

    let mut uname = [0u8; 16];
    let ulen = username.len().min(16);
    uname[..ulen].copy_from_slice(&username[..ulen]);

    hmac_sha1(&pwd, &uname)
}

pub fn compute_sik(
    k_uid: &[u8],
    console_rand: &[u8; 16],
    bmc_rand: &[u8; 16],
    shared_secret: &[u8],
    console_sid: u32,
    bmc_sid: u32,
    privilege: u8,
    username: &[u8],
) -> [u8; SHA1_LEN] {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(console_rand);
    data.extend_from_slice(bmc_rand);
    data.extend_from_slice(shared_secret);
    data.extend_from_slice(&console_sid.to_le_bytes());
    data.extend_from_slice(&bmc_sid.to_le_bytes());
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(k_uid, &data)
}

pub fn derive_k1(sik: &[u8]) -> [u8; SHA1_LEN] {
    let mut data = [0u8; SHA1_LEN];
    data[0] = 0x01;
    hmac_sha1(sik, &data)
}

pub fn derive_k2(sik: &[u8]) -> [u8; AES_BLOCK] {
    let mut data = [0u8; SHA1_LEN];
    data[0] = 0x02;
    let full = hmac_sha1(sik, &data);
    let mut k2 = [0u8; AES_BLOCK];
    k2.copy_from_slice(&full[..AES_BLOCK]);
    k2
}

pub fn compute_rakp2_hmac(
    k_uid: &[u8],
    console_sid: u32,
    bmc_rand: &[u8; 16],
    privilege: u8,
    username: &[u8],
) -> [u8; HMAC_SHA1_96_LEN] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&console_sid.to_le_bytes());
    data.extend_from_slice(bmc_rand);
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1_96(k_uid, &data)
}

pub fn compute_rakp3_hmac(
    sik: &[u8],
    console_rand: &[u8; 16],
    bmc_sid: u32,
    console_sid: u32,
    privilege: u8,
    username: &[u8],
) -> [u8; HMAC_SHA1_96_LEN] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(console_rand);
    data.extend_from_slice(&bmc_sid.to_le_bytes());
    data.extend_from_slice(&console_sid.to_le_bytes());
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1_96(sik, &data)
}

pub fn compute_rakp4_hmac(
    sik: &[u8],
    console_rand: &[u8; 16],
    bmc_rand: &[u8; 16],
    console_sid: u32,
    privilege: u8,
    username: &[u8],
) -> [u8; HMAC_SHA1_96_LEN] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(console_rand);
    data.extend_from_slice(bmc_rand);
    data.extend_from_slice(&console_sid.to_le_bytes());
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1_96(sik, &data)
}

pub fn compute_session_icv(k1: &[u8], data: &[u8]) -> [u8; HMAC_SHA1_96_LEN] {
    hmac_sha1_96(k1, data)
}
