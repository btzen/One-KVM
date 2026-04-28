//! IPMI 2.0 RMCP+ LAN server for One-KVM.
//!
//! Implements IPMI 2.0 RMCP+ (`ipmitool -I lanplus`) with HMAC-SHA1 + AES-CBC-128.
//!
//! Reuses the existing ATX power control:
//! - **Power On** → ATX short press
//! - **Hard Reset / Power Cycle** → ATX reset
//! - **Get Power Status** → ATX LED sensor
//!
//! ```bash
//! ipmitool -I lanplus -H <host> -U <user> -P <pass> chassis power status
//! ipmitool -I lanplus -H <host> -U <user> -P <pass> chassis power on
//! ipmitool -I lanplus -H <host> -U <user> -P <pass> chassis power reset
//! ```

mod crypto;
mod protocol;
mod rmcpp;
mod session;

use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::atx::{AtxController, PowerStatus};
use protocol::*;
use session::SessionManager;

pub use crate::config::IpmiConfig;

const MAX_PACKET_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpmiPowerState {
    On,
    Off,
    Unknown,
}

impl From<PowerStatus> for IpmiPowerState {
    fn from(value: PowerStatus) -> Self {
        match value {
            PowerStatus::On => Self::On,
            PowerStatus::Off => Self::Off,
            PowerStatus::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedPowerAction {
    NoOp,
    PowerShort,
    PowerLong,
    Reset,
}

fn build_chassis_status_payload(state: IpmiPowerState) -> Result<[u8; 4], u8> {
    match state {
        IpmiPowerState::On => Ok([0x01, 0x00, 0x00, 0x00]),
        IpmiPowerState::Off => Ok([0x00, 0x00, 0x00, 0x00]),
        IpmiPowerState::Unknown => Err(CC_COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE),
    }
}

fn plan_chassis_control(action: u8, state: IpmiPowerState) -> Result<PlannedPowerAction, u8> {
    match action {
        0x00 | 0x01 | 0x03 => {}
        _ => return Err(CC_INVALID_DATA),
    }

    match (action, state) {
        (_, IpmiPowerState::Unknown) => Err(CC_COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE),
        (0x00, IpmiPowerState::On) => Ok(PlannedPowerAction::PowerLong),
        (0x00, IpmiPowerState::Off) => Ok(PlannedPowerAction::NoOp),
        (0x01, IpmiPowerState::On) => Ok(PlannedPowerAction::NoOp),
        (0x01, IpmiPowerState::Off) => Ok(PlannedPowerAction::PowerShort),
        (0x03, IpmiPowerState::On) => Ok(PlannedPowerAction::Reset),
        (0x03, IpmiPowerState::Off) => Ok(PlannedPowerAction::NoOp),
        _ => Err(CC_INVALID_DATA),
    }
}

fn validate_rmcpp_icv(full_payload: &[u8], k1: &[u8; 20]) -> bool {
    const ICV_LEN: usize = 12;

    if full_payload.len() < 12 + 2 + ICV_LEN {
        return false;
    }

    let Some(authcode_offset) = full_payload.len().checked_sub(ICV_LEN) else {
        return false;
    };
    let expected = crypto::compute_session_icv(k1, &full_payload[..authcode_offset]);
    crypto::ct_eq(&expected, &full_payload[authcode_offset..])
}

pub struct IpmiService {
    atx: Arc<RwLock<Option<AtxController>>>,
    config: IpmiConfig,
    sessions: Arc<RwLock<SessionManager>>,
    bmc_guid: [u8; 16],
}

impl IpmiService {
    pub fn new(atx: Arc<RwLock<Option<AtxController>>>, config: IpmiConfig) -> Arc<Self> {
        let mut bmc_guid = [0u8; 16];
        for b in bmc_guid.iter_mut() {
            *b = rand::random::<u8>();
        }
        bmc_guid[6] = (bmc_guid[6] & 0x0F) | 0x40;
        bmc_guid[8] = (bmc_guid[8] & 0x3F) | 0x80;

        Arc::new(Self {
            atx,
            config,
            sessions: Arc::new(RwLock::new(SessionManager::new())),
            bmc_guid,
        })
    }

    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.port);
        let socket = UdpSocket::bind(&addr).await?;
        info!("IPMI server listening on UDP {}", addr);

        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    debug!("IPMI: received {} bytes from {}", len, peer);
                    if let Some(response) = self.handle_packet(&buf[..len]).await {
                        if let Err(e) = socket.send_to(&response, peer).await {
                            warn!("IPMI: failed to send response to {}: {}", peer, e);
                        }
                    }
                }
                Err(e) => {
                    error!("IPMI: recv error: {}", e);
                }
            }
        }
    }

    async fn handle_packet(&self, data: &[u8]) -> Option<Vec<u8>> {
        let header = RmcpHeader::read(data)?;
        let payload = &data[4..];

        match header.class {
            RMCP_CLASS_ASF => self.handle_asf(&header, payload),
            RMCP_CLASS_IPMI => self.handle_ipmi(&header, payload).await,
            _ => {
                debug!("IPMI: unknown RMCP class 0x{:02x}", header.class);
                None
            }
        }
    }

    fn handle_asf(&self, header: &RmcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let msg = AsfMessage::read(payload)?;
        if msg.msg_type != ASF_TYPE_PING || msg.iana != ASF_IANA {
            return None;
        }
        debug!("IPMI: ASF Presence Ping (tag={})", msg.tag);
        let pong = AsfMessage::pong(msg.tag);
        let mut out = Vec::with_capacity(64);
        RmcpHeader::new_asf(header.sequence).write(&mut out);
        pong.write(&mut out);
        Some(out)
    }

    async fn handle_ipmi(&self, rmcp: &RmcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 10 {
            return None;
        }
        let auth_type = payload[0];

        if auth_type == AUTH_TYPE_RMCP_PLUS {
            return self.handle_rmcpp(rmcp, payload).await;
        }

        if auth_type == 0x00 {
            return self.handle_pre_session(rmcp, payload);
        }

        debug!(
            "IPMI: ignoring non-RMCP+ packet auth_type=0x{:02x}",
            auth_type
        );
        None
    }

    fn handle_pre_session(&self, rmcp: &RmcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let msg_len = *payload.get(9)? as usize;
        let msg_data = payload.get(10..10 + msg_len)?;
        let msg = IpmiMessage::read(msg_data)?;

        match msg.command {
            CMD_GET_CHANNEL_AUTH_CAPS => {
                self.handle_get_channel_auth(rmcp, &msg, payload)
            }
            CMD_GET_CHANNEL_CIPHER_SUITES => {
                let resp_msg = msg.build_response(CC_OK, vec![
                    CHANNEL_CURRENT,
                    0xC0, 0x03, 0x01, 0x01, 0x01,
                ]);
                self.wrap_v15_response(rmcp, &resp_msg, payload)
            }
            CMD_GET_DEVICE_ID => {
                let resp_msg = msg.build_response(CC_OK, self.device_id_data());
                self.wrap_v15_response(rmcp, &resp_msg, payload)
            }
            _ => {
                debug!("IPMI: unhandled pre-session cmd=0x{:02x}", msg.command);
                None
            }
        }
    }

    fn handle_get_channel_auth(
        &self,
        rmcp: &RmcpHeader,
        msg: &IpmiMessage,
        req_payload: &[u8],
    ) -> Option<Vec<u8>> {
        let resp_msg = msg.build_response(CC_OK, vec![
            CHANNEL_CURRENT,
            0x84,
            0x04,
            0x03,
            0x00, 0x00, 0x00,
            0x00,
        ]);
        self.wrap_v15_response(rmcp, &resp_msg, req_payload)
    }

    fn wrap_v15_response(
        &self,
        rmcp: &RmcpHeader,
        resp_msg: &IpmiMessage,
        req_payload: &[u8],
    ) -> Option<Vec<u8>> {
        let msg_bytes = resp_msg.to_bytes();
        let mut out = Vec::with_capacity(256);
        RmcpHeader::new_ipmi(rmcp.sequence).write(&mut out);
        out.push(0x00);
        out.extend_from_slice(&req_payload[1..5]);
        out.extend_from_slice(&req_payload[5..9]);
        out.push(msg_bytes.len() as u8);
        out.extend_from_slice(&msg_bytes);
        Some(out)
    }

    // ════════════════════════════════════════
    // IPMI 2.0 RMCP+ handling
    // ════════════════════════════════════════

    async fn handle_rmcpp(&self, rmcp: &RmcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let hdr = RmcppSessionHeader::read(payload)?;
        let payload_data = payload.get(12..12 + hdr.payload_length as usize)?;

        debug!(
            "IPMI RMCP+: payload_type=0x{:02x} sid=0x{:08x} seq={} len={}",
            hdr.payload_type, hdr.session_id, hdr.session_seq, hdr.payload_length
        );

        match hdr.payload_type_raw() {
            PAYLOAD_TYPE_OPEN_SESSION_REQ => {
                self.handle_open_session(rmcp, &hdr, payload_data).await
            }
            PAYLOAD_TYPE_RAKP_1 => self.handle_rakp1(rmcp, &hdr, payload_data).await,
            PAYLOAD_TYPE_RAKP_3 => self.handle_rakp3(rmcp, &hdr, payload_data).await,
            PAYLOAD_TYPE_IPMI => {
                self.handle_rmcpp_ipmi(rmcp, &hdr, payload_data, payload)
                    .await
            }
            _ => {
                debug!(
                    "IPMI: unknown RMCP+ payload type 0x{:02x}",
                    hdr.payload_type_raw()
                );
                None
            }
        }
    }

    async fn handle_open_session(
        &self,
        rmcp: &RmcpHeader,
        _hdr: &RmcppSessionHeader,
        payload_data: &[u8],
    ) -> Option<Vec<u8>> {
        let req = rmcpp::OpenSessionRequest::parse(payload_data)?;

        let mut sessions = self.sessions.write().await;
        let bmc_session_id = sessions.create_session(req.console_session_id);

        let session = sessions.get_session_mut(bmc_session_id)?;
        session.auth_algo = req.auth_algo;
        session.integrity_algo = req.integrity_algo;
        session.conf_algo = req.conf_algo;
        session.privilege = if req.privilege == 0 {
            PRIV_ADMINISTRATOR
        } else {
            req.privilege.min(PRIV_ADMINISTRATOR)
        };
        session.touch();

        debug!(
            "IPMI: Open Session console_id=0x{:08x} bmc_id=0x{:08x} auth={} integ={} conf={}",
            req.console_session_id, bmc_session_id, req.auth_algo, req.integrity_algo, req.conf_algo
        );

        let resp_payload = req.build_response(bmc_session_id);

        let mut out = Vec::with_capacity(256);
        RmcpHeader::new_ipmi(rmcp.sequence).write(&mut out);
        let resp_hdr = RmcppSessionHeader {
            auth_type: AUTH_TYPE_RMCP_PLUS,
            payload_type: PAYLOAD_TYPE_OPEN_SESSION_RSP,
            session_id: 0,
            session_seq: 0,
            payload_length: resp_payload.len() as u16,
        };
        resp_hdr.write(&mut out);
        out.extend_from_slice(&resp_payload);
        Some(out)
    }

    async fn handle_rakp1(
        &self,
        rmcp: &RmcpHeader,
        _hdr: &RmcppSessionHeader,
        payload_data: &[u8],
    ) -> Option<Vec<u8>> {
        let rakp1 = rmcpp::Rakp1Request::parse(payload_data)?;

        debug!(
            "IPMI: RAKP1 bmc_sid=0x{:08x} priv=0x{:02x} user={}",
            rakp1.bmc_session_id,
            rakp1.privilege,
            String::from_utf8_lossy(&rakp1.username)
        );

        let mut sessions = self.sessions.write().await;
        let (console_session_id, resp_payload) = rmcpp::handle_rakp1(
            &mut sessions,
            &rakp1,
            self.config.password.as_bytes(),
            &self.config.username,
            &self.bmc_guid,
        )?;

        let mut out = Vec::with_capacity(256);
        RmcpHeader::new_ipmi(rmcp.sequence).write(&mut out);
        let resp_hdr = RmcppSessionHeader {
            auth_type: AUTH_TYPE_RMCP_PLUS,
            payload_type: PAYLOAD_TYPE_RAKP_2,
            session_id: console_session_id,
            session_seq: 0,
            payload_length: resp_payload.len() as u16,
        };
        resp_hdr.write(&mut out);
        out.extend_from_slice(&resp_payload);
        Some(out)
    }

    async fn handle_rakp3(
        &self,
        rmcp: &RmcpHeader,
        _hdr: &RmcppSessionHeader,
        payload_data: &[u8],
    ) -> Option<Vec<u8>> {
        let rakp3 = rmcpp::Rakp3Request::parse(payload_data)?;

        debug!("IPMI: RAKP3 bmc_sid=0x{:08x}", rakp3.bmc_session_id);

        let mut sessions = self.sessions.write().await;
        let (sid, resp_payload) = rmcpp::handle_rakp3(
            &mut sessions,
            &rakp3,
            self.config.password.as_bytes(),
            &self.bmc_guid,
        )?;

        let session = sessions.get_session(sid)?;
        let console_sid = session.console_session_id;

        let mut out = Vec::with_capacity(256);
        RmcpHeader::new_ipmi(rmcp.sequence).write(&mut out);
        let resp_hdr = RmcppSessionHeader {
            auth_type: AUTH_TYPE_RMCP_PLUS,
            payload_type: PAYLOAD_TYPE_RAKP_4,
            session_id: console_sid,
            session_seq: 0,
            payload_length: resp_payload.len() as u16,
        };
        resp_hdr.write(&mut out);
        out.extend_from_slice(&resp_payload);
        Some(out)
    }

    async fn handle_rmcpp_ipmi(
        &self,
        rmcp: &RmcpHeader,
        hdr: &RmcppSessionHeader,
        payload_data: &[u8],
        _full_payload: &[u8],
    ) -> Option<Vec<u8>> {
        if hdr.session_id == 0 {
            let msg = IpmiMessage::read(payload_data)?;
            if msg.command == CMD_GET_CHANNEL_CIPHER_SUITES {
                return self.handle_get_cipher_suites(rmcp, hdr, &msg);
            }
            if msg.command == CMD_GET_DEVICE_ID {
                let resp_msg = msg.build_response(CC_OK, self.device_id_data());
                return self.build_rmcpp_plain_response(rmcp, hdr, &resp_msg);
            }
            return None;
        }

        let session_id = hdr.session_id;
        let is_close_session;

        let (k1, k2, console_sid) = {
            let mut sessions = self.sessions.write().await;
            let session = sessions.get_session_mut(session_id)?;
            if !session.is_active {
                return None;
            }
            session.client_seq = hdr.session_seq;
            session.touch();
            (session.k1?, session.k2?, session.console_session_id)
        };

        if !hdr.is_authenticated() {
            warn!("IPMI: rejecting unauthenticated active-session packet");
            return None;
        }

        if !validate_rmcpp_icv(_full_payload, &k1) {
            warn!("IPMI: rejecting packet with invalid session authcode");
            return None;
        }

        let ipmi_msg_bytes = if hdr.is_encrypted() {
            let iv = payload_data.get(..16)?;
            let ciphertext = &payload_data[16..];
            crypto::ipmi2_decrypt(&k2, iv, ciphertext)?
        } else {
            payload_data.to_vec()
        };

        let msg = IpmiMessage::read(&ipmi_msg_bytes)?;

        debug!(
            "IPMI RMCP+ cmd: netfn=0x{:02x} cmd=0x{:02x}",
            msg.netfn, msg.command
        );

        is_close_session = msg.netfn == NETFN_APP_REQ && msg.command == CMD_CLOSE_SESSION;

        let resp_msg = self.dispatch_rmcpp_command(&msg).await;

        let result = self
            .build_rmcpp_encrypted_response(rmcp, session_id, console_sid, &k1, &k2, &resp_msg)
            .await;

        if is_close_session {
            let mut sessions = self.sessions.write().await;
            sessions.remove_session(session_id);
            debug!("IPMI: session 0x{:08x} removed", session_id);
        }

        result
    }

    fn handle_get_cipher_suites(
        &self,
        rmcp: &RmcpHeader,
        hdr: &RmcppSessionHeader,
        msg: &IpmiMessage,
    ) -> Option<Vec<u8>> {
        let resp_msg = msg.build_response(CC_OK, vec![
            CHANNEL_CURRENT,
            0xC0, 0x03, 0x01, 0x01, 0x01,
        ]);
        self.build_rmcpp_plain_response(rmcp, hdr, &resp_msg)
    }

    async fn dispatch_rmcpp_command(&self, msg: &IpmiMessage) -> IpmiMessage {
        match (msg.netfn, msg.command) {
            (NETFN_APP_REQ, CMD_SET_SESSION_PRIVILEGE) => {
                let priv_level = msg.data.first().copied().unwrap_or(PRIV_ADMINISTRATOR);
                debug!("IPMI: set privilege 0x{:02x}", priv_level);
                msg.build_response(CC_OK, vec![priv_level.min(PRIV_ADMINISTRATOR)])
            }
            (NETFN_APP_REQ, CMD_CLOSE_SESSION) => {
                debug!("IPMI: close session (RMCP+)");
                msg.build_response(CC_OK, vec![])
            }
            (NETFN_APP_REQ, CMD_GET_DEVICE_ID) => {
                msg.build_response(CC_OK, self.device_id_data())
            }
            (NETFN_CHASSIS_REQ, CMD_GET_CHASSIS_STATUS) => {
                let state = self.get_power_state().await;
                debug!("IPMI: chassis status -> {:?}", state);
                match build_chassis_status_payload(state) {
                    Ok(payload) => msg.build_response(CC_OK, payload.to_vec()),
                    Err(completion_code) => msg.build_response(completion_code, vec![]),
                }
            }
            (NETFN_CHASSIS_REQ, CMD_CHASSIS_CONTROL) => {
                let action = msg.data.first().copied().unwrap_or(0xFF);
                let state = self.get_power_state().await;
                debug!("IPMI: chassis control action=0x{:02x} state={:?}", action, state);
                match plan_chassis_control(action, state) {
                    Ok(plan) => match self.exec_planned_power_action(plan).await {
                        Ok(()) => msg.build_response(CC_OK, vec![]),
                        Err(e) => {
                            warn!("IPMI: chassis control failed: {}", e);
                            msg.build_response(0xFF, vec![])
                        }
                    },
                    Err(completion_code) => msg.build_response(completion_code, vec![]),
                }
            }
            _ => {
                debug!(
                    "IPMI: unhandled RMCP+ netfn=0x{:02x} cmd=0x{:02x}",
                    msg.netfn, msg.command
                );
                msg.build_response(CC_INVALID_COMMAND, vec![])
            }
        }
    }

    // ════════════════════════════════════════
    // ATX power actions
    // ════════════════════════════════════════

    async fn exec_planned_power_action(
        &self,
        action: PlannedPowerAction,
    ) -> crate::error::Result<()> {
        match action {
            PlannedPowerAction::NoOp => Ok(()),
            PlannedPowerAction::PowerShort => {
                debug!("IPMI: power up (short press)");
                self.atx_power_short().await
            }
            PlannedPowerAction::PowerLong => {
                debug!("IPMI: power down (long press)");
                self.atx_power_long().await
            }
            PlannedPowerAction::Reset => {
                debug!("IPMI: hard reset");
                self.atx_reset().await
            }
        }
    }

    async fn get_power_state(&self) -> IpmiPowerState {
        let atx_guard = self.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => IpmiPowerState::from(atx.power_status().await),
            None => IpmiPowerState::Unknown,
        }
    }

    async fn atx_power_short(&self) -> crate::error::Result<()> {
        let atx_guard = self.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => atx.power_short().await,
            None => Err(crate::error::AppError::Config(
                "ATX controller not initialized".to_string(),
            )),
        }
    }

    async fn atx_power_long(&self) -> crate::error::Result<()> {
        let atx_guard = self.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => atx.power_long().await,
            None => Err(crate::error::AppError::Config(
                "ATX controller not initialized".to_string(),
            )),
        }
    }

    async fn atx_reset(&self) -> crate::error::Result<()> {
        let atx_guard = self.atx.read().await;
        match atx_guard.as_ref() {
            Some(atx) => atx.reset().await,
            None => Err(crate::error::AppError::Config(
                "ATX controller not initialized".to_string(),
            )),
        }
    }

    // ════════════════════════════════════════
    // Response builders
    // ════════════════════════════════════════

    fn device_id_data(&self) -> Vec<u8> {
        vec![
            0x00, 0x01, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn build_rmcpp_plain_response(
        &self,
        rmcp: &RmcpHeader,
        req_hdr: &RmcppSessionHeader,
        resp_msg: &IpmiMessage,
    ) -> Option<Vec<u8>> {
        let msg_bytes = resp_msg.to_bytes();
        let mut out = Vec::with_capacity(256);
        RmcpHeader::new_ipmi(rmcp.sequence).write(&mut out);
        let resp_hdr = RmcppSessionHeader {
            auth_type: AUTH_TYPE_RMCP_PLUS,
            payload_type: PAYLOAD_TYPE_IPMI,
            session_id: req_hdr.session_id,
            session_seq: 0,
            payload_length: msg_bytes.len() as u16,
        };
        resp_hdr.write(&mut out);
        out.extend_from_slice(&msg_bytes);
        Some(out)
    }

    async fn build_rmcpp_encrypted_response(
        &self,
        rmcp: &RmcpHeader,
        session_id: u32,
        console_session_id: u32,
        k1: &[u8; 20],
        k2: &[u8; 16],
        resp_msg: &IpmiMessage,
    ) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_session_mut(session_id)?;
        let seq = session.server_seq;
        session.server_seq = session.server_seq.wrapping_add(1);
        session.touch();
        drop(sessions);

        let msg_bytes = resp_msg.to_bytes();
        let (iv, ciphertext) = crypto::ipmi2_encrypt(k2, &msg_bytes);

        let mut payload_data = Vec::with_capacity(iv.len() + ciphertext.len());
        payload_data.extend_from_slice(&iv);
        payload_data.extend_from_slice(&ciphertext);

        let ptype = PAYLOAD_TYPE_IPMI | PAYLOAD_FLAG_ENCRYPTED | PAYLOAD_FLAG_AUTHENTICATED;

        let mut integrity_input = Vec::with_capacity(256);
        integrity_input.push(AUTH_TYPE_RMCP_PLUS);
        integrity_input.push(ptype);
        integrity_input.extend_from_slice(&console_session_id.to_le_bytes());
        integrity_input.extend_from_slice(&seq.to_le_bytes());
        integrity_input.extend_from_slice(&(payload_data.len() as u16).to_le_bytes());
        integrity_input.extend_from_slice(&payload_data);

        let pad_needed = (4 - ((integrity_input.len() + 2) % 4)) % 4;
        integrity_input.extend(std::iter::repeat(0xFFu8).take(pad_needed));
        integrity_input.push(pad_needed as u8);
        integrity_input.push(0x07);

        let icv = crypto::compute_session_icv(k1, &integrity_input);

        let mut out = Vec::with_capacity(512);
        RmcpHeader::new_ipmi(rmcp.sequence).write(&mut out);
        let resp_hdr = RmcppSessionHeader {
            auth_type: AUTH_TYPE_RMCP_PLUS,
            payload_type: ptype,
            session_id: console_session_id,
            session_seq: seq,
            payload_length: payload_data.len() as u16,
        };
        resp_hdr.write(&mut out);
        out.extend_from_slice(&payload_data);
        out.extend(std::iter::repeat(0xFFu8).take(pad_needed));
        out.push(pad_needed as u8);
        out.push(0x07);
        out.extend_from_slice(&icv);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_commands_are_gated_by_current_power_state() {
        assert_eq!(
            plan_chassis_control(0x01, IpmiPowerState::Off),
            Ok(PlannedPowerAction::PowerShort)
        );
        assert_eq!(
            plan_chassis_control(0x01, IpmiPowerState::On),
            Ok(PlannedPowerAction::NoOp)
        );
        assert_eq!(
            plan_chassis_control(0x00, IpmiPowerState::On),
            Ok(PlannedPowerAction::PowerLong)
        );
        assert_eq!(
            plan_chassis_control(0x00, IpmiPowerState::Off),
            Ok(PlannedPowerAction::NoOp)
        );
        assert_eq!(
            plan_chassis_control(0x03, IpmiPowerState::On),
            Ok(PlannedPowerAction::Reset)
        );
        assert_eq!(
            plan_chassis_control(0x03, IpmiPowerState::Off),
            Ok(PlannedPowerAction::NoOp)
        );
    }

    #[test]
    fn unsupported_or_unsafe_power_commands_fail_closed() {
        assert_eq!(plan_chassis_control(0x02, IpmiPowerState::On), Err(0xCC));
        assert_eq!(plan_chassis_control(0x05, IpmiPowerState::On), Err(0xCC));
        assert_eq!(plan_chassis_control(0x01, IpmiPowerState::Unknown), Err(0xD5));
    }

    #[test]
    fn chassis_status_payload_requires_known_power_state() {
        assert_eq!(
            build_chassis_status_payload(IpmiPowerState::On),
            Ok([0x01, 0x00, 0x00, 0x00])
        );
        assert_eq!(
            build_chassis_status_payload(IpmiPowerState::Off),
            Ok([0x00, 0x00, 0x00, 0x00])
        );
        assert_eq!(build_chassis_status_payload(IpmiPowerState::Unknown), Err(0xD5));
    }
}
