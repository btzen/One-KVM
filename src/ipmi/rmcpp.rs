//! RMCP+ (IPMI 2.0) session establishment: Open Session and RAKP handling.

use super::crypto;
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
        if data.len() < 32 {
            return None;
        }
        let message_tag = data[0];
        let privilege = data[1];
        let console_session_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let mut auth_algo = 0u8;
        let mut integrity_algo = 0u8;
        let mut conf_algo = 0u8;

        for i in 0..3 {
            let base = 8 + i * 8;
            if base + 8 > data.len() {
                break;
            }
            let algo_type = data[base];
            let algo_id = data[base + 4];
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
        let privilege = if self.privilege == 0 {
            0x04
        } else {
            self.privilege.min(0x04)
        };

        let mut out = Vec::with_capacity(36);
        out.push(self.message_tag);
        out.push(0x00);
        out.push(privilege);
        out.push(0x00);
        out.extend_from_slice(&self.console_session_id.to_le_bytes());
        out.extend_from_slice(&bmc_session_id.to_le_bytes());

        for (algo_type, algo_id) in [
            (0u8, self.auth_algo),
            (1u8, self.integrity_algo),
            (2u8, self.conf_algo),
        ] {
            out.push(algo_type);
            out.extend_from_slice(&[0x00, 0x00]);
            out.push(0x08);
            out.push(algo_id);
            out.extend_from_slice(&[0x00, 0x00, 0x00]);
        }

        out
    }
}

pub struct Rakp1Request {
    pub message_tag: u8,
    pub bmc_session_id: u32,
    pub console_rand: [u8; 16],
    pub privilege: u8,
    pub username: Vec<u8>,
}

impl Rakp1Request {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        let message_tag = data[0];
        let bmc_session_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let console_rand: [u8; 16] = data[8..24].try_into().ok()?;
        let privilege = data[24];

        let username_len = data[27] as usize;
        let offset = 28;
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

    let console_session_id = session.console_session_id;
    let username = rakp1.username.clone();

    let k_uid = crypto::compute_k_uid(password);

    let rakp2_hmac = crypto::compute_rakp2_hmac(
        &k_uid,
        console_session_id,
        session_id,
        &rakp1.console_rand,
        &bmc_rand,
        bmc_guid,
        rakp1.privilege,
        &username,
    );

    session.console_rand = Some(rakp1.console_rand);
    session.bmc_rand = Some(bmc_rand);
    session.sik = None;
    session.k1 = None;
    session.k2 = None;
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
    resp.extend_from_slice(&rakp2_hmac);

    Some((console_session_id, resp))
}

pub struct Rakp3Request {
    pub message_tag: u8,
    pub bmc_session_id: u32,
    pub integrity_check: [u8; 20],
}

impl Rakp3Request {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        let message_tag = data[0];
        let bmc_session_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let integrity_check: [u8; 20] = data[8..28].try_into().ok()?;

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
    password: &[u8],
    bmc_guid: &[u8; 16],
) -> Option<(u32, Vec<u8>)> {
    let session_id = rakp3.bmc_session_id;
    let session = sessions.get_session_mut(session_id)?;

    let console_session_id = session.console_session_id;
    let console_rand = session.console_rand?;
    let bmc_rand = session.bmc_rand?;
    let username = session.username.as_deref().unwrap_or("").as_bytes();
    let privilege = session.privilege;
    let k_uid = crypto::compute_k_uid(password);

    let expected_hmac = crypto::compute_rakp3_hmac(
        &k_uid,
        &bmc_rand,
        console_session_id,
        privilege,
        username,
    );

    if !crypto::ct_eq(&expected_hmac, &rakp3.integrity_check) {
        tracing::warn!("IPMI: RAKP3 integrity check failed");
        sessions.remove_session(session_id);
        return None;
    }

    let sik = crypto::compute_sik(&k_uid, &console_rand, &bmc_rand, privilege, username);
    let k1 = crypto::derive_k1(&sik);
    let k2 = crypto::derive_k2(&sik);

    let rakp4_hmac = crypto::compute_rakp4_hmac(
        &sik,
        &console_rand,
        session_id,
        bmc_guid,
    );

    session.sik = Some(sik);
    session.k1 = Some(k1);
    session.k2 = Some(k2);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_session_request_parses_ipmitool_layout() {
        let request = [
            0x01,
            0x04,
            0x00,
            0x00,
            0x44,
            0x33,
            0x22,
            0x11,
            0x00,
            0x00,
            0x00,
            0x08,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x08,
            0x01,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x08,
            0x01,
            0x00,
            0x00,
            0x00,
        ];

        let parsed = OpenSessionRequest::parse(&request).expect("request");
        assert_eq!(parsed.message_tag, 0x01);
        assert_eq!(parsed.privilege, 0x04);
        assert_eq!(parsed.console_session_id, 0x1122_3344);
        assert_eq!(parsed.auth_algo, 0x01);
        assert_eq!(parsed.integrity_algo, 0x01);
        assert_eq!(parsed.conf_algo, 0x01);
    }

    #[test]
    fn open_session_response_places_privilege_and_ids_at_standard_offsets() {
        let request = OpenSessionRequest {
            message_tag: 0x01,
            privilege: 0x04,
            console_session_id: 0x1122_3344,
            auth_algo: 0x01,
            integrity_algo: 0x01,
            conf_algo: 0x01,
        };

        let response = request.build_response(0x5566_7788);
        assert_eq!(response[0], 0x01);
        assert_eq!(response[1], 0x00);
        assert_eq!(response[2], 0x04);
        assert_eq!(response[3], 0x00);
        assert_eq!(&response[4..8], &0x1122_3344u32.to_le_bytes());
        assert_eq!(&response[8..12], &0x5566_7788u32.to_le_bytes());
        assert_eq!(response[12], 0x00);
        assert_eq!(response[15], 0x08);
        assert_eq!(response[20], 0x01);
        assert_eq!(response[28], 0x02);
    }

    #[test]
    fn rakp1_request_parses_fixed_ipmitool_layout() {
        let mut request = [0u8; 44];
        request[0] = 0x00;
        request[4..8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        request[8..24].copy_from_slice(&[
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        request[24] = 0x04;
        request[27] = 0x05;
        request[28..33].copy_from_slice(b"admin");

        let parsed = Rakp1Request::parse(&request).expect("rakp1");
        assert_eq!(parsed.message_tag, 0x00);
        assert_eq!(parsed.bmc_session_id, 0x1122_3344);
        assert_eq!(parsed.console_rand, [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        assert_eq!(parsed.privilege, 0x04);
        assert_eq!(parsed.username, b"admin");
    }
}
