//! RMCP+ (IPMI 2.0) session establishment: Open Session and RAKP handling.

use super::crypto;
use super::protocol::*;
use super::session::SessionManager;

pub struct OpenSessionRequest {
    pub message_tag: u8,
    pub privilege: u8,
    pub console_session_id: u32,
    pub auth_algo: u8,
    pub integrity_algo: u8,
    pub conf_algo: u8,
}

impl OpenSessionRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 34 {
            return None;
        }
        let message_tag = data[0];
        let privilege = data[1];
        let console_session_id = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);

        let mut auth_algo = 0u8;
        let mut integrity_algo = 0u8;
        let mut conf_algo = 0u8;

        for i in 0..3 {
            let base = 10 + i * 8;
            if base + 8 > data.len() {
                break;
            }
            let algo_type = data[base];
            let algo_id = data[base + 2];
            match algo_type {
                0 => auth_algo = algo_id,
                1 => integrity_algo = algo_id,
                2 => conf_algo = algo_id,
                _ => {}
            }
        }

        Some(Self {
            message_tag,
            privilege,
            console_session_id,
            auth_algo,
            integrity_algo,
            conf_algo,
        })
    }

    pub fn build_response(&self, bmc_session_id: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(38);
        out.push(self.message_tag);
        out.push(0x00);
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&self.console_session_id.to_le_bytes());
        out.extend_from_slice(&bmc_session_id.to_le_bytes());

        for (algo_type, algo_id) in [(0u8, self.auth_algo), (1u8, self.integrity_algo), (2u8, self.conf_algo)] {
            out.push(algo_type);
            out.push(0x08);
            out.push(algo_id);
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        out
    }
}

pub struct Rakp1Request {
    pub message_tag: u8,
    pub bmc_session_id: u32,
    pub console_rand: [u8; 16],
    pub privilege: u8,
    pub dh_generator: Vec<u8>,
    pub dh_prime: Vec<u8>,
    pub console_public: Vec<u8>,
    pub username: Vec<u8>,
}

impl Rakp1Request {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 26 {
            return None;
        }
        let message_tag = data[0];
        let bmc_session_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let console_rand: [u8; 16] = data[6..22].try_into().ok()?;
        let privilege = data[22];

        let mut offset = 26;

        let gen_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let dh_generator = data.get(offset..offset + gen_len)?.to_vec();
        offset += gen_len;

        let prime_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let dh_prime = data.get(offset..offset + prime_len)?.to_vec();
        offset += prime_len;

        let pub_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let console_public = data.get(offset..offset + pub_len)?.to_vec();
        offset += pub_len;

        let username_len = *data.get(offset)? as usize;
        offset += 1;
        let username = if username_len > 0 {
            data.get(offset..offset + username_len)?.to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            message_tag,
            bmc_session_id,
            console_rand,
            privilege,
            dh_generator,
            dh_prime,
            console_public,
            username,
        })
    }
}

pub fn handle_rakp1(
    sessions: &mut SessionManager,
    rakp1: &Rakp1Request,
    password: &[u8],
    expected_username: &str,
    bmc_guid: &[u8; 16],
) -> Option<(u32, Vec<u8>)> {
    let session_id = rakp1.bmc_session_id;
    let session = sessions.get_session_mut(session_id)?;

    let config_username = expected_username.as_bytes();
    if rakp1.username != config_username {
        tracing::warn!(
            "IPMI: RAKP1 username mismatch: got '{}'",
            String::from_utf8_lossy(&rakp1.username)
        );
        sessions.remove_session(session_id);
        return None;
    }

    let mut bmc_rand = [0u8; 16];
    for b in bmc_rand.iter_mut() {
        *b = rand::random::<u8>();
    }

    let (dh_private, bmc_public) =
        crypto::dh_generate_keypair(&rakp1.dh_prime, &rakp1.dh_generator);

    let shared_secret =
        crypto::dh_shared_secret(&rakp1.dh_prime, &rakp1.console_public, &dh_private);

    let console_session_id = session.console_session_id;
    let username = rakp1.username.clone();

    let k_uid = crypto::compute_k_uid(password, &username);

    let sik = crypto::compute_sik(
        &k_uid,
        &rakp1.console_rand,
        &bmc_rand,
        &shared_secret,
        console_session_id,
        session_id,
        rakp1.privilege,
        &username,
    );

    let k1 = crypto::derive_k1(&sik);
    let k2 = crypto::derive_k2(&sik);

    let rakp2_hmac = crypto::compute_rakp2_hmac(
        &k_uid,
        console_session_id,
        &bmc_rand,
        rakp1.privilege,
        &username,
    );

    session.console_rand = Some(rakp1.console_rand);
    session.bmc_rand = Some(bmc_rand);
    session.dh_private = Some(dh_private);
    session.dh_shared_secret = Some(shared_secret);
    session.sik = Some(sik);
    session.k1 = Some(k1);
    session.k2 = Some(k2);
    session.username = Some(String::from_utf8_lossy(&username).to_string());
    session.privilege = rakp1.privilege;
    session.touch();

    let mut resp = Vec::with_capacity(128);
    resp.push(rakp1.message_tag);
    resp.push(0x00);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&console_session_id.to_le_bytes());
    resp.extend_from_slice(&bmc_rand);
    resp.extend_from_slice(bmc_guid);
    resp.extend_from_slice(&(bmc_public.len() as u16).to_le_bytes());
    resp.extend_from_slice(&bmc_public);
    resp.extend_from_slice(&rakp2_hmac);

    Some((console_session_id, resp))
}

pub struct Rakp3Request {
    pub message_tag: u8,
    pub bmc_session_id: u32,
    pub integrity_check: [u8; 12],
}

impl Rakp3Request {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let message_tag = data[0];
        let bmc_session_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let integrity_check: [u8; 12] = data[8..20].try_into().ok()?;

        Some(Self {
            message_tag,
            bmc_session_id,
            integrity_check,
        })
    }
}

pub fn handle_rakp3(
    sessions: &mut SessionManager,
    rakp3: &Rakp3Request,
) -> Option<(u32, Vec<u8>)> {
    let session_id = rakp3.bmc_session_id;
    let session = sessions.get_session_mut(session_id)?;

    let sik = session.sik?;
    let console_session_id = session.console_session_id;
    let console_rand = session.console_rand?;
    let bmc_rand = session.bmc_rand?;
    let username = session.username.as_deref().unwrap_or("").as_bytes();
    let privilege = session.privilege;

    let expected_hmac = crypto::compute_rakp3_hmac(
        &sik,
        &console_rand,
        session_id,
        console_session_id,
        privilege,
        username,
    );

    let mut diff = 0u8;
    for i in 0..12 {
        diff |= expected_hmac[i] ^ rakp3.integrity_check[i];
    }
    if diff != 0 {
        tracing::warn!("IPMI: RAKP3 integrity check failed");
        sessions.remove_session(session_id);
        return None;
    }

    let rakp4_hmac = crypto::compute_rakp4_hmac(
        &sik,
        &console_rand,
        &bmc_rand,
        console_session_id,
        privilege,
        username,
    );

    session.is_active = true;
    session.touch();

    tracing::debug!(
        "IPMI: RMCP+ session activated id=0x{:08x}",
        session_id
    );

    let mut resp = Vec::with_capacity(32);
    resp.push(rakp3.message_tag);
    resp.push(0x00);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&console_session_id.to_le_bytes());
    resp.extend_from_slice(&rakp4_hmac);

    Some((session_id, resp))
}
