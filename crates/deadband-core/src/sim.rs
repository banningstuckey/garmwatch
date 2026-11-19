//! The simulated plant: a small virtual facility that produces *real*
//! Ethernet/IP/TCP frames carrying real Modbus/TCP traffic, on a
//! believable schedule.
//!
//! This is Deadband's built-in lab. The frames are byte-for-byte what a
//! capture of a real plant would contain (correct checksums included),
//! so the parser, store, and detection layers are exercised honestly —
//! the GUI never fakes its data. The plant is deterministic: same seed,
//! same traffic, which is what makes pipeline tests possible.
//!
//! The roster models a textbook Purdue layout:
//!
//! - Office PC (Level 4) — ordinary IT chatter toward the historian.
//! - Plant Historian (Level 3) — slow archival polls of both PLCs.
//! - Operator HMI (Level 2) — fast process polls; occasional setpoint
//!   writes (the only writes in normal operation — Phase 4's rules will
//!   lean on exactly that fact).
//! - Line 1 / Line 2 PLCs (Level 1) — answer polls, accept HMI writes.

use crate::model::{Device, DeviceRole, PurdueLevel};
use crate::source::Packet;
use std::net::{IpAddr, Ipv4Addr};

/// Fixed seed: the plant behaves identically on every run.
const SEED: u64 = 0xDEAD_BAAD_0000_0001;

/// Tiny deterministic PRNG (xorshift64). Not cryptographic — it only
/// needs to make register values wander believably.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Value in `0..n`.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// One simulated device, as ground truth. (A real deployment learns
/// these facts passively in Phase 3; the lab hands them to the engine
/// so discovery has something true to show.)
#[derive(Debug, Clone, Copy)]
pub struct PlantDevice {
    pub ip: [u8; 4],
    pub mac: &'static str,
    pub level: PurdueLevel,
    pub role: DeviceRole,
    pub label: &'static str,
}

pub const OFFICE_PC: PlantDevice = PlantDevice {
    ip: [10, 0, 4, 10],
    mac: "02:db:00:00:04:0a",
    level: PurdueLevel::Enterprise,
    role: DeviceRole::OfficePc,
    label: "Office PC",
};
pub const HISTORIAN: PlantDevice = PlantDevice {
    ip: [10, 0, 3, 20],
    mac: "02:db:00:00:03:20",
    level: PurdueLevel::Operations,
    role: DeviceRole::Historian,
    label: "Plant Historian",
};
pub const HMI: PlantDevice = PlantDevice {
    ip: [10, 0, 2, 10],
    mac: "02:db:00:00:02:0a",
    level: PurdueLevel::Supervisory,
    role: DeviceRole::Hmi,
    label: "Operator HMI",
};
pub const PLC1: PlantDevice = PlantDevice {
    ip: [10, 0, 1, 11],
    mac: "02:db:00:00:01:0b",
    level: PurdueLevel::Control,
    role: DeviceRole::Plc,
    label: "Line 1 PLC",
};
pub const PLC2: PlantDevice = PlantDevice {
    ip: [10, 0, 1, 12],
    mac: "02:db:00:00:01:0c",
    level: PurdueLevel::Control,
    role: DeviceRole::Plc,
    label: "Line 2 PLC",
};
/// The DNP3 segment (Step B): a SCADA master polling two RTUs —
/// the electric/water side of the plant, speaking DNP3 on port
/// 20000 where the PLC side speaks Modbus.
pub const SCADA_MASTER: PlantDevice = PlantDevice {
    ip: [10, 0, 3, 30],
    mac: "02:db:00:00:03:1e",
    level: PurdueLevel::Operations,
    role: DeviceRole::Hmi,
    label: "SCADA Master",
};
pub const RTU1: PlantDevice = PlantDevice {
    ip: [10, 0, 1, 21],
    mac: "02:db:00:00:01:15",
    level: PurdueLevel::Control,
    role: DeviceRole::Rtu,
    label: "North RTU",
};
pub const RTU2: PlantDevice = PlantDevice {
    ip: [10, 0, 1, 22],
    mac: "02:db:00:00:01:16",
    level: PurdueLevel::Control,
    role: DeviceRole::Rtu,
    label: "South RTU",
};

/// A roster device's DNP3 link address (the master is 1, the
/// outstations are 101/102 — DNP3 carries its own addressing
/// inside the protocol, separate from IP).
pub fn dnp_addr(ip: [u8; 4]) -> u16 {
    if ip == SCADA_MASTER.ip {
        1
    } else if ip == RTU1.ip {
        101
    } else if ip == RTU2.ip {
        102
    } else {
        200
    }
}

/// The plant's full device roster.
pub fn roster() -> Vec<Device> {
    [OFFICE_PC, HISTORIAN, HMI, PLC1, PLC2, SCADA_MASTER, RTU1, RTU2]
        .iter()
        .map(|def| {
            let mut device = Device::new(IpAddr::V4(Ipv4Addr::from(def.ip)), 0);
            device.mac = Some(def.mac.to_string());
            device.level = Some(def.level);
            device.role = def.role;
            device.label = Some(def.label.to_string());
            device
        })
        .collect()
}

/// Looks up a roster device by IP (label/level/role ground truth).
pub fn device_by_ip(ip: [u8; 4]) -> Option<PlantDevice> {
    [OFFICE_PC, HISTORIAN, HMI, PLC1, PLC2, SCADA_MASTER, RTU1, RTU2]
        .into_iter()
        .find(|def| def.ip == ip)
}

// ---------------------------------------------------------------------
// Frame builders. Public because Phase 3's PCAP work and the parser
// tests craft frames the same way.

fn parse_mac(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, part) in mac.split(':').enumerate().take(6) {
        out[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    out
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a full Ethernet II + IPv4 + TCP frame carrying `payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_frame(
    src_mac: &str,
    dst_mac: &str,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    seq: u32,
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut frame = Vec::with_capacity(14 + ip_len);
    frame.extend_from_slice(&parse_mac(dst_mac));
    frame.extend_from_slice(&parse_mac(src_mac));
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header (checksum filled in after assembly).
    let ip_start = frame.len();
    frame.push(0x45); // version 4, IHL 5
    frame.push(0); // DSCP/ECN
    frame.extend_from_slice(&(ip_len as u16).to_be_bytes());
    frame.extend_from_slice(&((seq & 0xFFFF) as u16).to_be_bytes()); // id
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    frame.push(64); // TTL
    frame.push(6); // TCP
    frame.extend_from_slice(&[0, 0]); // checksum placeholder
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    let ip_sum = checksum(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());

    // TCP header + payload.
    let tcp_start = frame.len();
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack
    frame.push(0x50); // data offset 5 words
    frame.push(0x18); // PSH + ACK
    frame.extend_from_slice(&8192u16.to_be_bytes()); // window
    frame.extend_from_slice(&[0, 0]); // checksum placeholder
    frame.extend_from_slice(&[0, 0]); // urgent pointer
    frame.extend_from_slice(payload);
    // TCP checksum covers a pseudo-header + the segment.
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[tcp_start..]);
    let tcp_sum = checksum(&pseudo);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_sum.to_be_bytes());
    frame
}

fn modbus_adu(transaction: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut adu = Vec::with_capacity(7 + pdu.len());
    adu.extend_from_slice(&transaction.to_be_bytes());
    adu.extend_from_slice(&0u16.to_be_bytes()); // protocol id: 0 = Modbus
    adu.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    adu.push(unit);
    adu.extend_from_slice(pdu);
    adu
}

/// A Modbus read request frame (function 1–4), client → PLC.
#[allow(clippy::too_many_arguments)]
pub fn build_modbus_read(
    src_mac: &str,
    dst_mac: &str,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    unit: u8,
    function: u8,
    address: u16,
    quantity: u16,
    seq: u32,
) -> Vec<u8> {
    let mut pdu = vec![function];
    pdu.extend_from_slice(&address.to_be_bytes());
    pdu.extend_from_slice(&quantity.to_be_bytes());
    let adu = modbus_adu((seq & 0xFFFF) as u16, unit, &pdu);
    build_tcp_frame(src_mac, dst_mac, src_ip, dst_ip, src_port, 502, &adu, seq)
}

/// A Modbus write-single-register request frame (function 6).
#[allow(clippy::too_many_arguments)]
pub fn build_modbus_write_single(
    src_mac: &str,
    dst_mac: &str,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    unit: u8,
    address: u16,
    value: u16,
    seq: u32,
) -> Vec<u8> {
    let mut pdu = vec![6u8];
    pdu.extend_from_slice(&address.to_be_bytes());
    pdu.extend_from_slice(&value.to_be_bytes());
    let adu = modbus_adu((seq & 0xFFFF) as u16, unit, &pdu);
    build_tcp_frame(src_mac, dst_mac, src_ip, dst_ip, src_port, 502, &adu, seq)
}

/// A Modbus read response frame, PLC → client, with register values.
#[allow(clippy::too_many_arguments)]
pub fn build_modbus_read_response(
    src_mac: &str,
    dst_mac: &str,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    dst_port: u16,
    unit: u8,
    function: u8,
    values: &[u16],
    seq: u32,
) -> Vec<u8> {
    let mut pdu = vec![function, (values.len() * 2) as u8];
    for value in values {
        pdu.extend_from_slice(&value.to_be_bytes());
    }
    let adu = modbus_adu((seq & 0xFFFF) as u16, unit, &pdu);
    build_tcp_frame(src_mac, dst_mac, src_ip, dst_ip, 502, dst_port, &adu, seq)
}

/// A Modbus write-single response: an echo of the request PDU.
#[allow(clippy::too_many_arguments)]
fn build_modbus_write_echo(
    plc: PlantDevice,
    client: PlantDevice,
    client_port: u16,
    unit: u8,
    address: u16,
    value: u16,
    seq: u32,
) -> Vec<u8> {
    let mut pdu = vec![6u8];
    pdu.extend_from_slice(&address.to_be_bytes());
    pdu.extend_from_slice(&value.to_be_bytes());
    let adu = modbus_adu((seq & 0xFFFF) as u16, unit, &pdu);
    build_tcp_frame(plc.mac, client.mac, plc.ip, client.ip, 502, client_port, &adu, seq)
}


/// The master's ephemeral port for DNP3 conversations.
pub const DNP_MASTER_PORT: u16 = 40003;

/// Builds one complete DNP3 frame (link header + CRC-armoured
/// blocks) around application bytes, inside a TCP frame on the
/// DNP3 port. Public for the parser tests and the scenarios.
pub fn build_dnp3(
    src: PlantDevice,
    dst: PlantDevice,
    app: &[u8],
    seq: u32,
) -> Vec<u8> {
    let from_master = src.ip == SCADA_MASTER.ip;
    let mut link = vec![0x05, 0x64, (5 + app.len()) as u8, if from_master { 0xC4 } else { 0x44 }];
    link.extend_from_slice(&dnp_addr(dst.ip).to_le_bytes());
    link.extend_from_slice(&dnp_addr(src.ip).to_le_bytes());
    let header_crc = crate::parse::dnp3_crc(&link[2..8]);
    link.extend_from_slice(&header_crc.to_le_bytes());
    for block in app.chunks(16) {
        link.extend_from_slice(block);
        let block_crc = crate::parse::dnp3_crc(block);
        link.extend_from_slice(&block_crc.to_le_bytes());
    }
    let (src_port, dst_port) = if from_master {
        (DNP_MASTER_PORT, crate::parse::DNP3_PORT)
    } else {
        (crate::parse::DNP3_PORT, DNP_MASTER_PORT)
    };
    build_tcp_frame(src.mac, dst.mac, src.ip, dst.ip, src_port, dst_port, &link, seq)
}

/// Application bytes for a DNP3 request: transport byte,
/// application control byte, function, then the object bytes.
fn dnp3_app(function: u8, objects: &[u8], seq: u32) -> Vec<u8> {
    let mut app = vec![0xC0 | (seq & 0x3F) as u8, 0xC0 | (seq & 0x0F) as u8, function];
    app.extend_from_slice(objects);
    app
}

/// A class-0 read poll, master → RTU (group 60 variation 1, all).
pub fn build_dnp3_poll(rtu: PlantDevice, seq: u32) -> Vec<u8> {
    build_dnp3(SCADA_MASTER, rtu, &dnp3_app(0x01, &[60, 1, 0x06], seq), seq)
}

/// The RTU's answer to a poll: response function, IIN bytes, then
/// a few analog input values (group 30) for flavour.
pub fn build_dnp3_poll_response(rtu: PlantDevice, values: &[u16], seq: u32) -> Vec<u8> {
    let mut objects = vec![30, 5, 0x00, 0, 3];
    for value in values.iter().take(4) {
        objects.extend_from_slice(&value.to_le_bytes());
    }
    let mut app = dnp3_app(0x81, &[], seq);
    // Responses carry two IIN bytes after the function code.
    app.truncate(3);
    app.extend_from_slice(&[0, 0]);
    app.extend_from_slice(&objects);
    build_dnp3(rtu, SCADA_MASTER, &app, seq)
}

/// A direct operate carrying one control relay output block
/// (group 12) — the master flipping an output on the RTU, the
/// DNP3 peer of a Modbus write.
pub fn build_dnp3_operate(rtu: PlantDevice, seq: u32) -> Vec<u8> {
    // CROB: qualifier 0x17, count 1, index 0, then the 5-byte
    // block (control code 0x04 latch off, count, on/off, status).
    let objects = [12, 1, 0x17, 1, 0, 0x04, 1, 10, 0, 0];
    build_dnp3(SCADA_MASTER, rtu, &dnp3_app(0x05, &objects, seq), seq)
}

/// Any DNP3 request with a chosen function code — restarts and
/// other rare commands the scenarios and tests need.
pub fn build_dnp3_command(
    src: PlantDevice,
    dst: PlantDevice,
    function: u8,
    objects: &[u8],
    seq: u32,
) -> Vec<u8> {
    build_dnp3(src, dst, &dnp3_app(function, objects, seq), seq)
}

// ---------------------------------------------------------------------
// The plant itself: a schedule of polls, writes, and chatter.

const HMI_PORT: u16 = 40001;
const HISTORIAN_PORT: u16 = 40002;
const OFFICE_PORT: u16 = 51000;

#[derive(Clone, Copy)]
enum Job {
    HmiPoll(PlantDevice),
    HistorianPoll(PlantDevice),
    HmiSetpointWrite,
    OfficeWeb,
    DnpPoll(PlantDevice),
    DnpOperate,
}

struct Scheduled {
    due_ms: i64,
    job: Job,
}

struct Pending {
    due_ms: i64,
    frame: Vec<u8>,
}

/// The virtual plant's state: virtual clock, sequence counters,
/// wandering register values, and what's due next.
pub struct Plant {
    clock_ms: i64,
    rng: Rng,
    seq: u32,
    /// Next setpoint the HMI will write (slowly drifting).
    setpoint: u16,
    schedule: Vec<Scheduled>,
    pending: Vec<Pending>,
}

impl Default for Plant {
    fn default() -> Self {
        Self::new()
    }
}

impl Plant {
    pub fn new() -> Plant {
        let mut schedule = Vec::new();
        // Staggered first fires so the log doesn't start in lockstep.
        schedule.push(Scheduled { due_ms: 100, job: Job::HmiPoll(PLC1) });
        schedule.push(Scheduled { due_ms: 600, job: Job::HmiPoll(PLC2) });
        schedule.push(Scheduled { due_ms: 2_500, job: Job::HistorianPoll(PLC1) });
        schedule.push(Scheduled { due_ms: 3_500, job: Job::HistorianPoll(PLC2) });
        schedule.push(Scheduled { due_ms: 20_000, job: Job::HmiSetpointWrite });
        schedule.push(Scheduled { due_ms: 5_000, job: Job::OfficeWeb });
        schedule.push(Scheduled { due_ms: 1_200, job: Job::DnpPoll(RTU1) });
        schedule.push(Scheduled { due_ms: 1_700, job: Job::DnpPoll(RTU2) });
        schedule.push(Scheduled { due_ms: 9_000, job: Job::DnpOperate });
        Plant {
            clock_ms: 0,
            rng: Rng(SEED),
            seq: 1000,
            setpoint: 420,
            schedule,
            pending: Vec::new(),
        }
    }

    fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    /// Register values for a read response: a slow random walk around
    /// a per-PLC base, so consecutive polls look alive, not random.
    fn register_values(&mut self, plc: PlantDevice, count: u16) -> Vec<u16> {
        let base: i32 = if plc.ip == PLC1.ip { 400 } else { 700 };
        (0..count)
            .map(|i| (base + i as i32 * 7 + self.rng.below(9) as i32 - 4) as u16)
            .collect()
    }

    fn queue_response(&mut self, after_ms: i64, frame: Vec<u8>) {
        let due = self.clock_ms + after_ms;
        self.pending.push(Pending { due_ms: due, frame });
    }

    fn latency(&mut self) -> i64 {
        8 + self.rng.below(18) as i64
    }

    fn run_job(&mut self, job: Job) -> Vec<u8> {
        match job {
            Job::HmiPoll(plc) => {
                let seq = self.next_seq();
                let frame = build_modbus_read(
                    HMI.mac, plc.mac, HMI.ip, plc.ip, HMI_PORT, 1, 3, 100, 10, seq,
                );
                let values = self.register_values(plc, 10);
                let rseq = self.next_seq();
                let response = build_modbus_read_response(
                    plc.mac, HMI.mac, plc.ip, HMI.ip, HMI_PORT, 1, 3, &values, rseq,
                );
                let latency = self.latency();
                self.queue_response(latency, response);
                frame
            }
            Job::HistorianPoll(plc) => {
                let seq = self.next_seq();
                let frame = build_modbus_read(
                    HISTORIAN.mac, plc.mac, HISTORIAN.ip, plc.ip, HISTORIAN_PORT, 1, 3, 0, 20, seq,
                );
                let values = self.register_values(plc, 20);
                let rseq = self.next_seq();
                let response = build_modbus_read_response(
                    plc.mac, HISTORIAN.mac, plc.ip, HISTORIAN.ip, HISTORIAN_PORT, 1, 3, &values,
                    rseq,
                );
                let latency = self.latency();
                self.queue_response(latency, response);
                frame
            }
            Job::HmiSetpointWrite => {
                // The setpoint wanders a step or two, then the HMI
                // writes it to Line 1 — normal operations, in the open.
                let drift = self.rng.below(5) as i32 - 2;
                self.setpoint = (self.setpoint as i32 + drift).clamp(380, 460) as u16;
                let seq = self.next_seq();
                let frame = build_modbus_write_single(
                    HMI.mac, PLC1.mac, HMI.ip, PLC1.ip, HMI_PORT, 1, 200, self.setpoint, seq,
                );
                let rseq = self.next_seq();
                let echo = build_modbus_write_echo(PLC1, HMI, HMI_PORT, 1, 200, self.setpoint, rseq);
                let latency = self.latency();
                self.queue_response(latency, echo);
                frame
            }
            Job::DnpPoll(rtu) => {
                let seq = self.next_seq();
                let frame = build_dnp3_poll(rtu, seq);
                let base: u16 = if rtu.ip == RTU1.ip { 220 } else { 540 };
                let values: Vec<u16> = (0..4)
                    .map(|i| base + i * 11 + self.rng.below(7) as u16)
                    .collect();
                let rseq = self.next_seq();
                let response = build_dnp3_poll_response(rtu, &values, rseq);
                let latency = self.latency();
                self.queue_response(latency, response);
                frame
            }
            Job::DnpOperate => {
                // The master works an output on the North RTU —
                // legitimate control, from the one device allowed.
                let seq = self.next_seq();
                let frame = build_dnp3_operate(RTU1, seq);
                let rseq = self.next_seq();
                let response = build_dnp3(RTU1, SCADA_MASTER, &dnp3_app(0x81, &[0, 0], rseq), rseq);
                let latency = self.latency();
                self.queue_response(latency, response);
                frame
            }
            Job::OfficeWeb => {
                let seq = self.next_seq();
                build_tcp_frame(
                    OFFICE_PC.mac,
                    HISTORIAN.mac,
                    OFFICE_PC.ip,
                    HISTORIAN.ip,
                    OFFICE_PORT,
                    443,
                    b"GET /reports HTTP/1.1\r\nHost: historian\r\n\r\n",
                    seq,
                )
            }
        }
    }

    fn rearm(job: &Job) -> i64 {
        match job {
            Job::HmiPoll(_) => 1_000,
            Job::HistorianPoll(_) => 5_000,
            Job::HmiSetpointWrite => 47_000,
            Job::OfficeWeb => 7_000,
            Job::DnpPoll(rtu) => {
                if rtu.ip == RTU1.ip {
                    2_000
                } else {
                    2_600
                }
            }
            Job::DnpOperate => 67_000,
        }
    }

    /// The next frame the plant produces, stamped `base_ms + virtual
    /// clock`. The plant never runs dry — there is always a next poll.
    pub fn next_packet(&mut self, base_ms: i64) -> Packet {
        // Earliest item wins: a queued response or a scheduled job.
        let next_job_due = self.schedule.iter().map(|s| s.due_ms).min().unwrap_or(i64::MAX);
        let next_resp_due = self.pending.iter().map(|p| p.due_ms).min().unwrap_or(i64::MAX);
        if next_resp_due <= next_job_due {
            let idx = self.pending.iter().position(|p| p.due_ms == next_resp_due).unwrap();
            let pending = self.pending.remove(idx);
            self.clock_ms = pending.due_ms;
            return Packet { timestamp_ms: base_ms + self.clock_ms, data: pending.frame };
        }
        let idx = self.schedule.iter().position(|s| s.due_ms == next_job_due).unwrap();
        self.clock_ms = self.schedule[idx].due_ms;
        let job = self.schedule[idx].job;
        let interval = Self::rearm(&job);
        let frame = self.run_job(job);
        self.schedule[idx].due_ms = self.clock_ms + interval;
        Packet { timestamp_ms: base_ms + self.clock_ms, data: frame }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse_packet, MODBUS_PORT};
    use crate::model::Protocol;

    #[test]
    fn roster_is_a_textbook_purdue_layout() {
        let devices = roster();
        assert_eq!(devices.len(), 8);
        assert!(devices.iter().any(|d| d.role == DeviceRole::Hmi));
        assert_eq!(devices.iter().filter(|d| d.role == DeviceRole::Plc).count(), 2);
        assert_eq!(devices.iter().filter(|d| d.role == DeviceRole::Rtu).count(), 2);
    }

    #[test]
    fn plant_is_deterministic() {
        let mut a = Plant::new();
        let mut b = Plant::new();
        for _ in 0..60 {
            assert_eq!(a.next_packet(0), b.next_packet(0));
        }
    }

    #[test]
    fn plant_traffic_parses_as_mostly_modbus() {
        let mut plant = Plant::new();
        let mut modbus = 0;
        let mut dnp3 = 0;
        let mut writes = 0;
        let mut total = 0;
        // ~90 virtual seconds: long enough for two setpoint writes.
        let mut last_ts = 0;
        while last_ts < 90_000 {
            let packet = plant.next_packet(0);
            last_ts = packet.timestamp_ms;
            let parsed = parse_packet(&packet).expect("plant frames must parse");
            total += 1;
            if parsed.protocol == Protocol::ModbusTcp {
                modbus += 1;
                if parsed.modbus.as_ref().map(|m| m.is_write).unwrap_or(false) {
                    writes += 1;
                    // In normal operation only the HMI writes.
                    assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::from(HMI.ip))));
                }
            }
            if let Some(mb) = parsed.modbus {
                if !mb.is_response {
                    assert_eq!(parsed.dst_port, Some(MODBUS_PORT));
                }
            }
            if parsed.protocol == Protocol::Dnp3 {
                dnp3 += 1;
                if let Some(dnp) = parsed.dnp3 {
                    if dnp.is_control {
                        // In normal operation only the master operates.
                        assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::from(SCADA_MASTER.ip))));
                    }
                    assert!(dnp.crc_ok, "sim frames must carry honest checksums");
                }
            }
        }
        assert!(total > 100, "expected a busy plant, got {total} packets");
        assert!(modbus > total / 2, "Modbus is still the plant's biggest language");
        assert!(dnp3 > total / 6, "the DNP3 segment is a real share of traffic");
        assert!(modbus + dnp3 > total * 9 / 10, "OT protocols dominate the plant");
        assert!(writes >= 1, "the HMI setpoint write must occur");
    }

    #[test]
    fn clock_never_runs_backwards() {
        let mut plant = Plant::new();
        let mut last = i64::MIN;
        for _ in 0..200 {
            let packet = plant.next_packet(1_000);
            assert!(packet.timestamp_ms >= last);
            last = packet.timestamp_ms;
        }
    }
}
