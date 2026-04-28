//! IPMI 2.0 RMCP+ protocol types, constants, and packet parsing.
//!
//! - RMCP/ASF presence ping/pong
//! - RMCP+ session header, Open Session, RAKP payloads
//! - IPMI message framing and checksums
//! - HMAC-SHA1-96 integrity, AES-CBC-128 encryption

#[allow(dead_code)]
pub const RMCP_PORT: u16 = 623;
pub const RMCP_VERSION_1: u8 = 0x06;

pub const RMCP_CLASS_ASF: u8 = 0x06;
pub const RMCP_CLASS_IPMI: u8 = 0x07;

pub const ASF_IANA: u32 = 0x0000_11BE;
pub const ASF_TYPE_PING: u8 = 0x80;
pub const ASF_TYPE_PONG: u8 = 0x40;

pub const NETFN_CHASSIS_REQ: u8 = 0x00;
#[allow(dead_code)]
pub const NETFN_CHASSIS_RSP: u8 = 0x01;
pub const NETFN_APP_REQ: u8 = 0x06;
#[allow(dead_code)]
pub const NETFN_APP_RSP: u8 = 0x07;

pub const CMD_GET_DEVICE_ID: u8 = 0x01;
pub const CMD_GET_CHANNEL_CIPHER_SUITES: u8 = 0x54;
pub const CMD_SET_SESSION_PRIVILEGE: u8 = 0x3B;
pub const CMD_CLOSE_SESSION: u8 = 0x3C;

pub const CMD_GET_CHASSIS_STATUS: u8 = 0x01;
pub const CMD_CHASSIS_CONTROL: u8 = 0x02;

pub const AUTH_TYPE_RMCP_PLUS: u8 = 0x06;

pub const PAYLOAD_TYPE_IPMI: u8 = 0x00;
pub const PAYLOAD_TYPE_OPEN_SESSION_REQ: u8 = 0x10;
pub const PAYLOAD_TYPE_OPEN_SESSION_RSP: u8 = 0x11;
pub const PAYLOAD_TYPE_RAKP_1: u8 = 0x12;
pub const PAYLOAD_TYPE_RAKP_2: u8 = 0x13;
pub const PAYLOAD_TYPE_RAKP_3: u8 = 0x14;
pub const PAYLOAD_TYPE_RAKP_4: u8 = 0x15;

pub const PAYLOAD_FLAG_AUTHENTICATED: u8 = 0x40;
pub const PAYLOAD_FLAG_ENCRYPTED: u8 = 0x80;

pub const PRIV_ADMINISTRATOR: u8 = 0x04;
pub const CHANNEL_CURRENT: u8 = 0x0E;

pub const CC_OK: u8 = 0x00;
pub const CC_INVALID_COMMAND: u8 = 0xC1;
#[allow(dead_code)]
pub const CC_INVALID_DATA: u8 = 0xCC;

pub const BMC_SLAVE_ADDR: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct RmcpHeader {
    pub version: u8,
    pub reserved: u8,
    pub sequence: u8,
    pub class: u8,
}

impl RmcpHeader {
    pub fn read(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        Some(Self {
            version: buf[0],
            reserved: buf[1],
            sequence: buf[2],
            class: buf[3],
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.push(self.reserved);
        out.push(self.sequence);
        out.push(self.class);
    }

    pub fn new_ipmi(sequence: u8) -> Self {
        Self {
            version: RMCP_VERSION_1,
            reserved: 0x00,
            sequence,
            class: RMCP_CLASS_IPMI,
        }
    }

    pub fn new_asf(sequence: u8) -> Self {
        Self {
            version: RMCP_VERSION_1,
            reserved: 0x00,
            sequence,
            class: RMCP_CLASS_ASF,
        }
    }
}

#[derive(Debug)]
pub struct AsfMessage {
    pub iana: u32,
    pub msg_type: u8,
    pub tag: u8,
    pub data: Vec<u8>,
}

impl AsfMessage {
    pub fn read(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let iana = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let msg_type = buf[4];
        let tag = buf[5];
        let data_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let data = buf.get(8..8 + data_len)?.to_vec();
        Some(Self {
            iana,
            msg_type,
            tag,
            data,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.iana.to_be_bytes());
        out.push(self.msg_type);
        out.push(self.tag);
        out.extend_from_slice(&[0x00, 0x00]);
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
    }

    pub fn pong(tag: u8) -> Self {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&ASF_IANA.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.push(0x81);
        data.push(0x00);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        Self {
            iana: ASF_IANA,
            msg_type: ASF_TYPE_PONG,
            tag,
            data,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpmiMessage {
    pub rs_addr: u8,
    pub netfn: u8,
    pub rs_lun: u8,
    pub rq_addr: u8,
    pub seq: u8,
    pub rq_lun: u8,
    pub command: u8,
    pub data: Vec<u8>,
}

impl IpmiMessage {
    pub fn read(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        let rs_addr = buf[0];
        let netfn_lun = buf[1];
        let rq_addr = buf[3];
        let seq_lun = buf[4];
        let command = buf[5];
        let data = if buf.len() > 7 {
            buf[6..buf.len() - 1].to_vec()
        } else {
            Vec::new()
        };
        Some(Self {
            rs_addr,
            netfn: netfn_lun >> 2,
            rs_lun: netfn_lun & 0x03,
            rq_addr,
            seq: seq_lun >> 2,
            rq_lun: seq_lun & 0x03,
            command,
            data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(self.rs_addr);
        out.push((self.netfn << 2) | (self.rs_lun & 0x03));
        let c1_pos = out.len();
        out.push(0x00);
        out.push(self.rq_addr);
        out.push((self.seq << 2) | (self.rq_lun & 0x03));
        out.push(self.command);
        out.extend_from_slice(&self.data);

        let sum1 = out[0].wrapping_add(out[1]);
        out[c1_pos] = (!sum1).wrapping_add(1);

        let mut sum2: u8 = 0;
        for b in &out[c1_pos + 1..] {
            sum2 = sum2.wrapping_add(*b);
        }
        out.push((!sum2).wrapping_add(1));
        out
    }

    pub fn build_response(&self, completion_code: u8, data: Vec<u8>) -> Self {
        let mut resp_data = vec![completion_code];
        resp_data.extend_from_slice(&data);
        Self {
            rs_addr: self.rq_addr,
            netfn: self.netfn + 1,
            rs_lun: self.rq_lun,
            rq_addr: BMC_SLAVE_ADDR,
            seq: self.seq,
            rq_lun: self.rs_lun,
            command: self.command,
            data: resp_data,
        }
    }
}

#[derive(Debug)]
pub struct RmcppSessionHeader {
    pub auth_type: u8,
    pub session_seq: u32,
    pub session_id: u32,
    pub payload_type: u8,
    pub payload_length: u16,
}

impl RmcppSessionHeader {
    pub fn read(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(Self {
            auth_type: buf[0],
            session_seq: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            session_id: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
            payload_type: buf[9],
            payload_length: u16::from_le_bytes([buf[10], buf[11]]),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.auth_type);
        out.extend_from_slice(&self.session_seq.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.push(self.payload_type);
        out.extend_from_slice(&self.payload_length.to_le_bytes());
    }

    pub fn is_encrypted(&self) -> bool {
        self.payload_type & PAYLOAD_FLAG_ENCRYPTED != 0
    }

    pub fn is_authenticated(&self) -> bool {
        self.payload_type & PAYLOAD_FLAG_AUTHENTICATED != 0
    }

    pub fn payload_type_raw(&self) -> u8 {
        self.payload_type & 0x3F
    }
}
