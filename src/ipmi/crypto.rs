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

pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&lhs, &rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_LEN] {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC key");
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
    let enc_pad_len = (AES_BLOCK - ((msg_bytes.len() + 1) % AES_BLOCK)) % AES_BLOCK;
    let mut plaintext = Vec::with_capacity(msg_bytes.len() + enc_pad_len + 1);
    plaintext.extend_from_slice(msg_bytes);
    plaintext.extend((1..=enc_pad_len).map(|index| index as u8));
    plaintext.push(enc_pad_len as u8);

    let mut iv = [0u8; AES_BLOCK];
    for b in iv.iter_mut() {
        *b = rand::random::<u8>();
    }

    let ciphertext = aes_cbc_encrypt(key, &iv, &plaintext);
    (iv.to_vec(), ciphertext)
}

pub fn ipmi2_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() % AES_BLOCK != 0 {
        return None;
    }
    let plaintext = aes_cbc_decrypt(key, iv, ciphertext);
    if plaintext.is_empty() {
        return None;
    }
    let enc_pad_len = *plaintext.last()? as usize;
    if plaintext.len() < enc_pad_len + 1 {
        return None;
    }
    let msg_len = plaintext.len() - enc_pad_len - 1;

    for (index, &pad) in plaintext[msg_len..msg_len + enc_pad_len].iter().enumerate() {
        if pad != (index + 1) as u8 {
            return None;
        }
    }

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

pub fn compute_k_uid(password: &[u8]) -> [u8; SHA1_LEN] {
    let mut out = [0u8; SHA1_LEN];
    let password_len = password.len().min(SHA1_LEN);
    out[..password_len].copy_from_slice(&password[..password_len]);
    out
}

pub fn compute_sik(
    k_uid: &[u8],
    console_rand: &[u8; 16],
    bmc_rand: &[u8; 16],
    privilege: u8,
    username: &[u8],
) -> [u8; SHA1_LEN] {
    let mut data = Vec::with_capacity(34 + username.len());
    data.extend_from_slice(console_rand);
    data.extend_from_slice(bmc_rand);
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(k_uid, &data)
}

pub fn derive_k1(sik: &[u8]) -> [u8; SHA1_LEN] {
    let data = [0x01u8; SHA1_LEN];
    hmac_sha1(sik, &data)
}

pub fn derive_k2(sik: &[u8]) -> [u8; AES_BLOCK] {
    let data = [0x02u8; SHA1_LEN];
    let full = hmac_sha1(sik, &data);
    let mut k2 = [0u8; AES_BLOCK];
    k2.copy_from_slice(&full[..AES_BLOCK]);
    k2
}

pub fn compute_rakp2_hmac(
    k_uid: &[u8],
    console_sid: u32,
    bmc_sid: u32,
    console_rand: &[u8; 16],
    bmc_rand: &[u8; 16],
    bmc_guid: &[u8; 16],
    privilege: u8,
    username: &[u8],
) -> [u8; SHA1_LEN] {
    let mut data = Vec::with_capacity(58 + username.len());
    data.extend_from_slice(&console_sid.to_le_bytes());
    data.extend_from_slice(&bmc_sid.to_le_bytes());
    data.extend_from_slice(console_rand);
    data.extend_from_slice(bmc_rand);
    data.extend_from_slice(bmc_guid);
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(k_uid, &data)
}

pub fn compute_rakp3_hmac(
    k_uid: &[u8],
    bmc_rand: &[u8; 16],
    console_sid: u32,
    privilege: u8,
    username: &[u8],
) -> [u8; SHA1_LEN] {
    let mut data = Vec::with_capacity(22 + username.len());
    data.extend_from_slice(bmc_rand);
    data.extend_from_slice(&console_sid.to_le_bytes());
    data.push(privilege);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(k_uid, &data)
}

pub fn compute_rakp4_hmac(
    sik: &[u8],
    console_rand: &[u8; 16],
    bmc_sid: u32,
    bmc_guid: &[u8; 16],
) -> [u8; HMAC_SHA1_96_LEN] {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(console_rand);
    data.extend_from_slice(&bmc_sid.to_le_bytes());
    data.extend_from_slice(bmc_guid);

    hmac_sha1_96(sik, &data)
}

pub fn compute_session_icv(k1: &[u8], data: &[u8]) -> [u8; HMAC_SHA1_96_LEN] {
    hmac_sha1_96(k1, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipmi2_encrypt_round_trips_with_confidentiality_padding() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        let (iv, ciphertext) = ipmi2_encrypt(&key, &payload);
        assert_eq!(iv.len(), AES_BLOCK);
        assert_eq!(ciphertext.len() % AES_BLOCK, 0);
        assert_eq!(ipmi2_decrypt(&key, &iv, &ciphertext), Some(payload.to_vec()));
    }

    #[test]
    fn sik_uses_console_rand_bmc_rand_role_and_username() {
        let k_uid = [0x11; SHA1_LEN];
        let console_rand = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let bmc_rand = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        ];
        let username = b"admin";

        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&console_rand);
        expected_input.extend_from_slice(&bmc_rand);
        expected_input.push(0x04);
        expected_input.push(username.len() as u8);
        expected_input.extend_from_slice(username);

        assert_eq!(
            compute_sik(&k_uid, &console_rand, &bmc_rand, 0x04, username),
            hmac_sha1(&k_uid, &expected_input)
        );
    }

    #[test]
    fn rakp2_hmac_uses_standard_field_order() {
        let k_uid = [0x22; SHA1_LEN];
        let console_rand = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let bmc_rand = [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        ];
        let bmc_guid = [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        ];
        let username = b"admin";

        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        expected_input.extend_from_slice(&0x5566_7788u32.to_le_bytes());
        expected_input.extend_from_slice(&console_rand);
        expected_input.extend_from_slice(&bmc_rand);
        expected_input.extend_from_slice(&bmc_guid);
        expected_input.push(0x04);
        expected_input.push(username.len() as u8);
        expected_input.extend_from_slice(username);

        assert_eq!(
            compute_rakp2_hmac(
                &k_uid,
                0x1122_3344,
                0x5566_7788,
                &console_rand,
                &bmc_rand,
                &bmc_guid,
                0x04,
                username,
            ),
            hmac_sha1(&k_uid, &expected_input)
        );
    }

    #[test]
    fn rakp3_hmac_uses_kuid_and_bmc_random() {
        let k_uid = [0x33; SHA1_LEN];
        let bmc_rand = [
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
        ];
        let username = b"admin";

        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&bmc_rand);
        expected_input.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        expected_input.push(0x04);
        expected_input.push(username.len() as u8);
        expected_input.extend_from_slice(username);

        assert_eq!(
            compute_rakp3_hmac(&k_uid, &bmc_rand, 0x1122_3344, 0x04, username),
            hmac_sha1(&k_uid, &expected_input)
        );
    }

    #[test]
    fn rakp4_hmac_uses_sik_console_random_bmc_id_and_guid() {
        let sik = [0x44; SHA1_LEN];
        let console_rand = [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
        ];
        let bmc_guid = [
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
        ];

        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&console_rand);
        expected_input.extend_from_slice(&0x5566_7788u32.to_le_bytes());
        expected_input.extend_from_slice(&bmc_guid);

        assert_eq!(
            compute_rakp4_hmac(&sik, &console_rand, 0x5566_7788, &bmc_guid),
            hmac_sha1_96(&sik, &expected_input)
        );
    }

    #[test]
    fn k1_and_k2_use_full_constant_blocks() {
        let sik = [0x55; SHA1_LEN];
        let expected_k1 = hmac_sha1(&sik, &[0x01; SHA1_LEN]);
        let expected_k2_full = hmac_sha1(&sik, &[0x02; SHA1_LEN]);

        assert_eq!(derive_k1(&sik), expected_k1);
        assert_eq!(derive_k2(&sik), expected_k2_full[..AES_BLOCK]);
    }
}
