//! Packet parsing: raw bytes in, structured facts out.
//!
//! The decode chain: Ethernet II → IPv4 → TCP/UDP → Modbus/TCP
//! (port 502) or DNP3 (port 20000, TCP or UDP). Anything else is
//! classified as plain TCP/UDP or rejected with a typed error.
//! Real-world captures harden the same code in Phase 3.
//!
//! Parsing is a pure function of the packet bytes. It performs no I/O
//! and — per the project's safety rules — never crafts response packets.
//! Real plant traffic is untrusted input: every length field is treated
//! as a lie until checked, and no input may cause a panic.

use crate::model::Protocol;
use crate::source::Packet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// The standard Modbus/TCP port.
pub const MODBUS_PORT: u16 = 502;

/// The standard DNP3 port (TCP and UDP).
pub const DNP3_PORT: u16 = 20000;

/// The Modbus facts lifted out of a Modbus/TCP packet — the fields
/// detection actually reasons about. (Full register values are process
/// data; a security monitor mostly needs *who commanded what, how*.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusInfo {
    /// Modbus unit/slave id the command addresses.
    pub unit_id: u8,
    /// Function code (1–4 reads, 5/6/15/16 writes, …). For exception
    /// responses the high bit is stripped, so this is the code of the
    /// request that failed.
    pub function_code: u8,
    /// True when the function code changes state on the target
    /// (write coil/register, etc.) — writes from unexpected sources are
    /// among the highest-signal events in OT monitoring.
    pub is_write: bool,
    /// True for responses travelling server → client; exception
    /// responses (the request was refused/failed) also set
    /// `is_exception`.
    pub is_response: bool,
    /// True when the server answered with a Modbus exception.
    pub is_exception: bool,
    /// Start address for read/write requests (register/coil number).
    pub address: Option<u16>,
    /// Quantity for read requests and multi-writes.
    pub quantity: Option<u16>,
    /// Value for single writes (function codes 5 and 6).
    pub value: Option<u16>,
    /// MBAP transaction identifier. A read response carries the
    /// transaction id of its request — the only link between a
    /// response and the address range it answers (responses do not
    /// repeat the address). Behavior recording pairs them with it.
    pub transaction_id: u16,
    /// Values decoded from a read response (functions 1–4):
    /// registers as themselves, coils/discrete inputs as 0/1, in
    /// address order starting at the paired request's start
    /// address. Empty for requests, writes, and exceptions.
    pub values: Vec<u16>,
}

impl ModbusInfo {
    /// Plain-English name of the function code, as operators and
    /// textbooks call it.
    pub fn function_name(&self) -> &'static str {
        match self.function_code {
            1 => "read coils",
            2 => "read discrete inputs",
            3 => "read holding registers",
            4 => "read input registers",
            5 => "write single coil",
            6 => "write single register",
            15 => "write multiple coils",
            16 => "write multiple registers",
            _ => "modbus function",
        }
    }
}


/// The DNP3 facts lifted out of a DNP3 frame — the second protocol
/// (Step B of the road to a real product; DNP3 is the SCADA language
/// of small electric and water utilities). DNP3 frames are
/// CRC-armoured in blocks; every checksum is verified, and a frame
/// whose structure parses but whose checksums fail is still
/// returned, flagged — corruption and fuzzing are signals, not
/// silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnp3Info {
    /// Link-layer source address (the sender's DNP3 address).
    pub src_addr: u16,
    /// Link-layer destination address (0xFFFF is broadcast).
    pub dst_addr: u16,
    /// Application function code (1 read, 5 direct operate, …).
    pub function_code: u8,
    /// True for responses (0x81) and unsolicited responses (0x82).
    pub is_response: bool,
    /// True for unsolicited responses (0x82) — an outstation
    /// speaking without being asked.
    pub is_unsolicited: bool,
    /// True when the command changes state on the target: a
    /// control-class function code, or a control object (group 12
    /// CROB / group 41 analog output) in the body. The DNP3 peer of
    /// a Modbus write.
    pub is_control: bool,
    /// True for cold (0x0D) or warm (0x0E) restart commands.
    pub is_restart: bool,
    /// True when a control object (group 12 / 41) was present.
    pub control_object: bool,
    /// True when every CRC in the frame verified.
    pub crc_ok: bool,
    /// True when addressed to the broadcast address 0xFFFF.
    pub broadcast: bool,
}

impl Dnp3Info {
    /// Plain-English name of the application function code.
    pub fn function_name(&self) -> &'static str {
        dnp3_function_name(self.function_code)
    }
}

/// Plain-English name of a DNP3 application function code.
pub fn dnp3_function_name(function_code: u8) -> &'static str {
    match function_code {
        0x01 => "read",
        0x02 => "write",
        0x03 => "select",
        0x04 => "operate",
        0x05 => "direct operate",
        0x06 => "direct operate (no ack)",
        0x07 => "immediate freeze",
        0x08 => "immediate freeze (no ack)",
        0x09 => "freeze and clear",
        0x0A => "freeze and clear (no ack)",
        0x0D => "cold restart",
        0x0E => "warm restart",
        0x10 => "initialize application",
        0x11 => "start application",
        0x12 => "stop application",
        0x13 => "save configuration",
        0x14 => "enable unsolicited responses",
        0x15 => "disable unsolicited responses",
        0x16 => "assign class",
        0x18 => "record current time",
        0x19 => "open file",
        0x1B => "delete file",
        0x81 => "response",
        0x82 => "unsolicited response",
        _ => "dnp3 function",
    }
}

/// DNP3 function codes that change state on the target: outputs,
/// stored data, configuration, application state, or the device
/// itself. (Freeze-without-clear only snapshots values, so 0x07 /
/// 0x08 are not control; 0x09 / 0x0A clear as they freeze.)
pub fn is_dnp3_control_function(function_code: u8) -> bool {
    matches!(
        function_code,
        0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x09 | 0x0A | 0x0D | 0x0E | 0x12 | 0x13 | 0x14 | 0x15
            | 0x1B | 0x1E | 0x20
    )
}

/// The DNP3 CRC (CRC-16/DNP: polynomial 0x3D65, reflected,
/// init 0x0000, final XOR 0xFFFF), as the link layer computes it
/// over the header and over each ≤16-byte data block.
pub fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc = (crc >> 8) ^ DNP3_CRC_TABLE[((crc ^ u16::from(byte)) & 0xFF) as usize];
    }
    !crc
}

const fn build_dnp3_crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA6BC } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static DNP3_CRC_TABLE: [u16; 256] = build_dnp3_crc_table();

fn u16le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Decodes one DNP3 frame, if the payload starts with one.
/// Returns `None` for payloads on other ports, without the
/// 0x05 0x64 start bytes, or too fragmented to hold a whole frame
/// (a passive monitor sees TCP segments, and a frame split across
/// segments is skipped rather than guessed at — noted in
/// docs/dnp3.md). Trailing bytes after the first complete frame
/// are ignored: a segment may carry several frames, and the first
/// is the one this packet is about.
fn parse_dnp3(src_port: Option<u16>, dst_port: Option<u16>, data: &[u8]) -> Option<Dnp3Info> {
    if src_port != Some(DNP3_PORT) && dst_port != Some(DNP3_PORT) {
        return None;
    }
    // Link header: start (2), length (1), control (1), destination
    // (2 LE), source (2 LE), header CRC (2 LE). The length counts
    // control + addresses + user data — never the CRCs.
    if data.len() < 10 || data[0] != 0x05 || data[1] != 0x64 {
        return None;
    }
    let length = data[2] as usize;
    if length < 5 {
        return None;
    }
    let user_len = length - 5;
    let blocks = user_len.div_ceil(16);
    let frame_len = 10 + user_len + 2 * blocks;
    if data.len() < frame_len || user_len < 3 {
        return None;
    }
    let dst_addr = u16le(data, 4);
    let src_addr = u16le(data, 6);
    let mut crc_ok = dnp3_crc(&data[2..8]) == u16le(data, 8);
    // User data arrives in blocks of at most 16 bytes, each trailed
    // by its own CRC.
    let mut user: Vec<u8> = Vec::with_capacity(user_len);
    let mut offset = 10;
    let mut remaining = user_len;
    while remaining > 0 {
        let take = remaining.min(16);
        let block = &data[offset..offset + take];
        if dnp3_crc(block) != u16le(data, offset + take) {
            crc_ok = false;
        }
        user.extend_from_slice(block);
        offset += take + 2;
        remaining -= take;
    }
    // Application layer: transport byte, application control byte,
    // function code, then object headers (requests) or IIN + data
    // (responses).
    let function_code = user[2];
    let is_response = matches!(function_code, 0x81 | 0x82);
    // Walk request object headers for control objects (group 12
    // control relay output block, group 41 analog output). The walk
    // is deliberately conservative: an unrecognised qualifier shape
    // ends it, keeping the groups already found.
    let mut control_object = false;
    if !is_response {
        let mut i = 3;
        let mut walked = 0;
        while i + 2 < user.len() && walked < 8 {
            let group = user[i];
            let qualifier = user[i + 2];
            if group == 12 || group == 41 {
                control_object = true;
            }
            walked += 1;
            let next = match qualifier {
                0x00 => i + 3 + 2,              // 8-bit start/stop
                0x01 => i + 3 + 4,              // 16-bit start/stop
                0x06 => i + 3,                  // all objects
                0x17 if group == 12 => {
                    // 8-bit count, one index byte, then 5-byte CROBs.
                    let count = *user.get(i + 3)? as usize;
                    i + 4 + 1 + count * 5
                }
                _ => break,
            };
            if next <= i || next > user.len() {
                break;
            }
            i = next;
        }
    }
    Some(Dnp3Info {
        src_addr,
        dst_addr,
        function_code,
        is_response,
        is_unsolicited: function_code == 0x82,
        is_control: !is_response && (is_dnp3_control_function(function_code) || control_object),
        is_restart: matches!(function_code, 0x0D | 0x0E),
        control_object,
        crc_ok,
        broadcast: dst_addr == 0xFFFF,
    })
}

/// Function codes that change state on the target device.
pub fn is_write_function(function_code: u8) -> bool {
    matches!(function_code, 5 | 6 | 15 | 16)
}

/// A packet after parsing: the conversation it belongs to and, for
/// Modbus/TCP, the decoded command summary.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPacket {
    /// Capture time, Unix milliseconds (carried from the raw packet).
    pub timestamp_ms: i64,
    /// Source IP, when an IP header was present.
    pub src_ip: Option<IpAddr>,
    /// Destination IP, when an IP header was present.
    pub dst_ip: Option<IpAddr>,
    /// Source port, for TCP/UDP.
    pub src_port: Option<u16>,
    /// Destination port, for TCP/UDP.
    pub dst_port: Option<u16>,
    /// Best protocol identification.
    pub protocol: Protocol,
    /// Decoded Modbus facts; `Some` only for Modbus/TCP packets.
    pub modbus: Option<ModbusInfo>,
    /// Decoded DNP3 facts; `Some` only for DNP3 packets.
    pub dnp3: Option<Dnp3Info>,
    /// Total frame length in bytes.
    pub length: usize,
}

/// Why a packet could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Zero-length input — nothing to parse.
    Empty,
    /// Truncated or malformed at a named layer ("ethernet", "ipv4", …).
    Malformed(&'static str),
    /// Well-formed, but a protocol Deadband does not decode.
    Unsupported(&'static str),
    /// The decoder for this protocol lands in a later phase.
    NotImplemented(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty packet"),
            ParseError::Malformed(layer) => write!(f, "malformed {layer} header"),
            ParseError::Unsupported(proto) => write!(f, "unsupported protocol: {proto}"),
            ParseError::NotImplemented(what) => write!(f, "not implemented yet: {what}"),
        }
    }
}

impl std::error::Error for ParseError {}

fn u16be(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Parses one raw packet (an Ethernet II frame, as every Deadband
/// source supplies) into a [`ParsedPacket`].
pub fn parse_packet(packet: &Packet) -> Result<ParsedPacket, ParseError> {
    let data = &packet.data;
    if data.is_empty() {
        return Err(ParseError::Empty);
    }
    // Ethernet II: 6 dst MAC + 6 src MAC + 2 EtherType.
    if data.len() < 14 {
        return Err(ParseError::Malformed("ethernet"));
    }
    let ethertype = u16be(data, 12);
    let payload = &data[14..];
    match ethertype {
        0x0800 => parse_ipv4(packet.timestamp_ms, payload, data.len()),
        0x86DD => Err(ParseError::Unsupported("ipv6")),
        _ => Err(ParseError::Unsupported("non-ip ethertype")),
    }
}

fn parse_ipv4(timestamp_ms: i64, ip: &[u8], frame_len: usize) -> Result<ParsedPacket, ParseError> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return Err(ParseError::Malformed("ipv4"));
    }
    let header_len = ((ip[0] & 0x0F) as usize) * 4;
    if header_len < 20 || ip.len() < header_len {
        return Err(ParseError::Malformed("ipv4"));
    }
    let total_len = u16be(ip, 2) as usize;
    if total_len < header_len || total_len > ip.len() {
        return Err(ParseError::Malformed("ipv4"));
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    let body = &ip[header_len..total_len];
    let mut parsed = ParsedPacket {
        timestamp_ms,
        src_ip: Some(src_ip),
        dst_ip: Some(dst_ip),
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown,
        modbus: None,
        dnp3: None,
        length: frame_len,
    };
    match ip[9] {
        6 => parse_tcp(&mut parsed, body)?,
        17 => parse_udp(&mut parsed, body)?,
        _ => return Err(ParseError::Unsupported("non-tcp/udp ip protocol")),
    }
    Ok(parsed)
}

fn parse_tcp(parsed: &mut ParsedPacket, tcp: &[u8]) -> Result<(), ParseError> {
    if tcp.len() < 20 {
        return Err(ParseError::Malformed("tcp"));
    }
    let header_len = ((tcp[12] >> 4) as usize) * 4;
    if header_len < 20 || tcp.len() < header_len {
        return Err(ParseError::Malformed("tcp"));
    }
    parsed.src_port = Some(u16be(tcp, 0));
    parsed.dst_port = Some(u16be(tcp, 2));
    parsed.protocol = Protocol::Tcp;
    let payload = &tcp[header_len..];
    if let Some(modbus) = parse_modbus(parsed.src_port, parsed.dst_port, payload) {
        parsed.protocol = Protocol::ModbusTcp;
        parsed.modbus = Some(modbus);
    } else if let Some(dnp3) = parse_dnp3(parsed.src_port, parsed.dst_port, payload) {
        parsed.protocol = Protocol::Dnp3;
        parsed.dnp3 = Some(dnp3);
    }
    Ok(())
}

fn parse_udp(parsed: &mut ParsedPacket, udp: &[u8]) -> Result<(), ParseError> {
    if udp.len() < 8 {
        return Err(ParseError::Malformed("udp"));
    }
    parsed.src_port = Some(u16be(udp, 0));
    parsed.dst_port = Some(u16be(udp, 2));
    parsed.protocol = Protocol::Udp;
    let payload = &udp[8..];
    if let Some(dnp3) = parse_dnp3(parsed.src_port, parsed.dst_port, payload) {
        parsed.protocol = Protocol::Dnp3;
        parsed.dnp3 = Some(dnp3);
    }
    Ok(())
}

/// Decodes a Modbus/TCP application data unit, if the payload is one.
/// Returns `None` for payloads on other ports or with a bad MBAP
/// header — those stay plain TCP rather than failing the packet.
fn parse_modbus(src_port: Option<u16>, dst_port: Option<u16>, adu: &[u8]) -> Option<ModbusInfo> {
    let is_response = src_port == Some(MODBUS_PORT);
    if !is_response && dst_port != Some(MODBUS_PORT) {
        return None;
    }
    // MBAP header: transaction id (2), protocol id (2, must be 0),
    // length (2, bytes following), unit id (1). Then the PDU.
    if adu.len() < 8 || u16be(adu, 2) != 0 {
        return None;
    }
    let declared = u16be(adu, 4) as usize;
    if declared < 2 || declared + 6 > adu.len() {
        return None;
    }
    let raw_function = adu[7];
    let is_exception = raw_function & 0x80 != 0;
    let function_code = raw_function & 0x7F;
    let mut info = ModbusInfo {
        unit_id: adu[6],
        function_code,
        is_write: !is_response && is_write_function(function_code),
        is_response,
        is_exception,
        address: None,
        quantity: None,
        value: None,
        transaction_id: u16be(adu, 0),
        values: Vec::new(),
    };
    if !is_response && adu.len() >= 12 {
        // Request PDUs for every function Deadband decodes carry the
        // start address at bytes 8–9; what follows depends on the code.
        info.address = Some(u16be(adu, 8));
        match function_code {
            1 | 2 | 3 | 4 | 15 | 16 => info.quantity = Some(u16be(adu, 10)),
            5 | 6 => info.value = Some(u16be(adu, 10)),
            _ => {}
        }
    }
    if is_response && !is_exception && (1..=4).contains(&function_code) && adu.len() >= 9 {
        // Read response PDU: function, byte count, then the data —
        // register pairs for 3/4, packed bits (LSB first) for 1/2.
        // Decode only what is actually present; a lying byte count
        // just yields fewer values.
        let byte_count = adu[8] as usize;
        let end = (9 + byte_count).min(adu.len());
        let data = &adu[9..end];
        match function_code {
            3 | 4 => {
                info.values = data.chunks_exact(2).map(|pair| u16be(pair, 0)).collect();
            }
            _ => {
                let mut values = Vec::with_capacity(data.len() * 8);
                for byte in data {
                    for bit in 0..8 {
                        values.push(u16::from((byte >> bit) & 1));
                    }
                }
                values.truncate(2000);
                info.values = values;
            }
        }
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim;

    #[test]
    fn empty_packet_is_rejected() {
        let packet = Packet { timestamp_ms: 0, data: Vec::new() };
        assert_eq!(parse_packet(&packet), Err(ParseError::Empty));
    }

    #[test]
    fn truncated_frames_fail_cleanly() {
        for len in [1usize, 10, 20, 40] {
            let packet = Packet { timestamp_ms: 0, data: vec![0u8; len] };
            assert!(parse_packet(&packet).is_err(), "len {len} must not parse");
        }
    }

    #[test]
    fn simulated_read_request_decodes() {
        // One full trip through the simulator's own frame builder: the
        // parser must see exactly the command the plant sent.
        let frame = sim::build_modbus_read(
            "02:db:00:00:00:0a",
            "02:db:00:00:00:11",
            [10, 0, 2, 10],
            [10, 0, 1, 11],
            40000,
            1,
            3,
            100,
            10,
            7,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: frame }).unwrap();
        assert_eq!(parsed.protocol, Protocol::ModbusTcp);
        assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 10))));
        assert_eq!(parsed.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 11))));
        assert_eq!(parsed.dst_port, Some(MODBUS_PORT));
        let mb = parsed.modbus.unwrap();
        assert_eq!(mb.function_code, 3);
        assert!(!mb.is_write);
        assert!(!mb.is_response);
        assert_eq!(mb.address, Some(100));
        assert_eq!(mb.quantity, Some(10));
    }

    #[test]
    fn simulated_write_and_response_decode() {
        let write = sim::build_modbus_write_single(
            "02:db:00:00:00:0a",
            "02:db:00:00:00:11",
            [10, 0, 2, 10],
            [10, 0, 1, 11],
            40000,
            1,
            200,
            425,
            9,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: write }).unwrap();
        let mb = parsed.modbus.unwrap();
        assert_eq!(mb.function_code, 6);
        assert!(mb.is_write);
        assert_eq!(mb.address, Some(200));
        assert_eq!(mb.value, Some(425));

        let response = sim::build_modbus_read_response(
            "02:db:00:00:00:11",
            "02:db:00:00:00:0a",
            [10, 0, 1, 11],
            [10, 0, 2, 10],
            40000,
            1,
            3,
            &[101, 102],
            7,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: response }).unwrap();
        let mb = parsed.modbus.unwrap();
        assert!(mb.is_response);
        assert!(!mb.is_write);
        assert_eq!(mb.function_code, 3);
    }

    #[test]
    fn plain_tcp_is_classified_not_decoded() {
        let frame = sim::build_tcp_frame(
            "02:db:00:00:00:0a",
            "02:db:00:00:00:20",
            [10, 0, 4, 10],
            [10, 0, 3, 20],
            51000,
            443,
            b"GET / HTTP/1.1\r\n\r\n",
            3,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: frame }).unwrap();
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_eq!(parsed.modbus, None);
        assert_eq!(parsed.dst_port, Some(443));
    }
}

#[cfg(test)]
mod dnp3_tests {
    use super::*;

    #[test]
    fn crc_matches_the_canonical_check_value() {
        // CRC-16/DNP over the standard check string.
        assert_eq!(dnp3_crc(b"123456789"), 0xEA82);
    }

    /// Builds a complete DNP3 frame the way the sim will: header +
    /// CRC'd blocks around the given application bytes.
    fn frame(src_addr: u16, dst_addr: u16, app: &[u8]) -> Vec<u8> {
        let mut out = vec![0x05, 0x64, (5 + app.len()) as u8, 0xC4];
        out.extend_from_slice(&dst_addr.to_le_bytes());
        out.extend_from_slice(&src_addr.to_le_bytes());
        let crc = dnp3_crc(&out[2..8]);
        out.extend_from_slice(&crc.to_le_bytes());
        for block in app.chunks(16) {
            out.extend_from_slice(block);
            let crc = dnp3_crc(block);
            out.extend_from_slice(&crc.to_le_bytes());
        }
        out
    }

    #[test]
    fn a_read_request_decodes() {
        // Transport, app control, READ (0x01), group 60 var 1, all.
        let data = frame(1, 101, &[0xC0, 0xC0, 0x01, 60, 1, 0x06]);
        let info = parse_dnp3(Some(40000), Some(DNP3_PORT), &data).expect("dnp3 frame");
        assert_eq!(info.src_addr, 1);
        assert_eq!(info.dst_addr, 101);
        assert_eq!(info.function_code, 0x01);
        assert!(!info.is_response && !info.is_control && info.crc_ok);
    }

    #[test]
    fn a_direct_operate_with_a_crob_is_control() {
        // DIRECT OPERATE (0x05), group 12 var 1 CROB, qualifier
        // 0x17, count 1, index 0, five CROB bytes.
        let data = frame(1, 101, &[0xC0, 0xC0, 0x05, 12, 1, 0x17, 1, 0, 0x06, 1, 0, 0, 0]);
        let info = parse_dnp3(Some(40000), Some(DNP3_PORT), &data).expect("dnp3 frame");
        assert!(info.is_control && info.control_object);
        assert_eq!(info.function_name(), "direct operate");
    }

    #[test]
    fn a_corrupt_frame_is_flagged_not_dropped() {
        let mut data = frame(1, 101, &[0xC0, 0xC0, 0x01, 60, 1, 0x06]);
        let last = data.len() - 3;
        data[last] ^= 0xFF; // flip a user-data byte; its block CRC now fails
        let info = parse_dnp3(Some(40000), Some(DNP3_PORT), &data).expect("still a frame");
        assert!(!info.crc_ok);
    }

    #[test]
    fn responses_and_restarts_classify() {
        let resp = frame(101, 1, &[0xC0, 0xC0, 0x81, 0x00, 0x00]);
        let info = parse_dnp3(Some(DNP3_PORT), Some(40000), &resp).expect("response");
        assert!(info.is_response && !info.is_control);
        let restart = frame(1, 101, &[0xC0, 0xC0, 0x0D]);
        let info = parse_dnp3(Some(40000), Some(DNP3_PORT), &restart).expect("restart");
        assert!(info.is_restart && info.is_control);
    }
}
