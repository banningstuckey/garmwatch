//! Behavior recording — per-device response profiles, kept from
//! day one (feature program, 2026-11-19).
//!
//! GarmWatch already stores events and connections. What it did not
//! keep was how each device *answers*: the actual register values a
//! Modbus server returns, which functions it answers, who polls it,
//! and at what rhythm. That is recorded here, passively, from the
//! responses already flowing past — a response profile per server.
//!
//! The consumer is the twin ("clone this system"): when a bad actor
//! is quarantined into the fake plant, the fake stack answers with
//! the *real* device's recorded values and rhythm instead of
//! generic fakes. Profiles are aggregates — ranges and counts, not
//! raw packets — so storage stays bounded no matter how long the
//! sensor runs.
//!
//! Pairing: a Modbus response does not repeat the address it
//! answers. The recorder pairs each read response with its request
//! by (client, server, transaction id) — the MBAP transaction id
//! exists for exactly this — and only then knows which addresses
//! the returned values belong to. Unpaired responses still count
//! toward the function mix; they just contribute no register values.

use crate::parse::ParsedPacket;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Register addresses tracked per device. Beyond this, new
/// addresses are counted in the mix but not ranged — a bound
/// against a scanner spraying reads across the whole address space.
pub const MAX_REGISTERS_PER_DEVICE: usize = 512;
/// Outstanding read requests remembered for pairing.
pub const MAX_PENDING: usize = 1024;
/// Poll gaps longer than this (an hour) do not feed the rhythm —
/// they are downtime or a replay seam, not a polling interval.
const MAX_POLL_GAP_MS: i64 = 3_600_000;

/// The observed range of one register (or coil, as 0/1) on one
/// device, under one read function.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegisterStat {
    /// Smallest value ever returned.
    pub min: u16,
    /// Largest value ever returned.
    pub max: u16,
    /// Most recent value returned.
    pub last: u16,
    /// How many values fed this stat.
    pub samples: u64,
}

impl RegisterStat {
    fn observe(&mut self, value: u16) {
        if self.samples == 0 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        self.last = value;
        self.samples += 1;
    }
}

/// Everything recorded about how one device behaves on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceProfile {
    /// The device (a Modbus server) this profile describes.
    pub ip: IpAddr,
    /// (read function, address) → observed value range.
    pub registers: HashMap<(u8, u16), RegisterStat>,
    /// Responses given, per function code.
    pub function_mix: HashMap<u8, u64>,
    /// Responses observed in total.
    pub responses: u64,
    /// Requests addressed to this device.
    pub polls: u64,
    /// Devices that poll this one.
    pub clients: HashSet<IpAddr>,
    /// Sum of gaps between consecutive requests (rhythm).
    pub interval_sum_ms: i64,
    /// Gaps counted into `interval_sum_ms`.
    pub interval_count: u64,
    /// Timestamp (ms) of the most recent request, for gap math.
    pub last_request_ms: Option<i64>,
    /// First observation, Unix seconds.
    pub first_seen_s: i64,
    /// Most recent observation, Unix seconds.
    pub last_seen_s: i64,
}

impl DeviceProfile {
    /// An empty profile for `ip`.
    pub fn new(ip: IpAddr) -> DeviceProfile {
        DeviceProfile {
            ip,
            registers: HashMap::new(),
            function_mix: HashMap::new(),
            responses: 0,
            polls: 0,
            clients: HashSet::new(),
            interval_sum_ms: 0,
            interval_count: 0,
            last_request_ms: None,
            first_seen_s: 0,
            last_seen_s: 0,
        }
    }

    /// The device's typical polling interval, when enough requests
    /// have been seen to say.
    pub fn mean_poll_interval_ms(&self) -> Option<i64> {
        if self.interval_count > 0 {
            Some(self.interval_sum_ms / self.interval_count as i64)
        } else {
            None
        }
    }

    fn touch(&mut self, ts_s: i64) {
        if self.first_seen_s == 0 || ts_s < self.first_seen_s {
            self.first_seen_s = ts_s;
        }
        self.last_seen_s = self.last_seen_s.max(ts_s);
    }
}

/// A read request waiting for its response.
#[derive(Debug, Clone, Copy)]
struct PendingRead {
    function: u8,
    address: u16,
    quantity: u16,
}

/// The recorder: feeds on every parsed packet, keeps every
/// profile. Pure and in-memory; the store persists it.
#[derive(Debug, Default)]
pub struct ProfileRecorder {
    profiles: HashMap<IpAddr, DeviceProfile>,
    pending: HashMap<(IpAddr, IpAddr, u16), PendingRead>,
}

impl ProfileRecorder {
    /// An empty recorder.
    pub fn new() -> ProfileRecorder {
        ProfileRecorder::default()
    }

    /// Observes one parsed packet. Returns the server whose
    /// profile changed, if any (the store uses it to know what to
    /// persist).
    pub fn observe(&mut self, parsed: &ParsedPacket) -> Option<IpAddr> {
        // DNP3 path (Step B): no register values to learn — an
        // outstation's answers are all function 0x81 — but the
        // poll rhythm, the clients, and the commands it is asked
        // to perform are exactly its behavior. Request functions
        // are counted in the mix namespaced at +128 so they can
        // never be confused with a Modbus code.
        if let Some(dnp) = &parsed.dnp3 {
            let (src, dst) = (parsed.src_ip?, parsed.dst_ip?);
            let ts_ms = parsed.timestamp_ms;
            let ts_s = ts_ms / 1000;
            if !dnp.is_response {
                let profile = self.profiles.entry(dst).or_insert_with(|| DeviceProfile::new(dst));
                profile.polls += 1;
                profile.clients.insert(src);
                if let Some(last) = profile.last_request_ms {
                    let gap = ts_ms - last;
                    if (0..MAX_POLL_GAP_MS).contains(&gap) {
                        profile.interval_sum_ms += gap;
                        profile.interval_count += 1;
                    }
                }
                profile.last_request_ms = Some(ts_ms);
                *profile.function_mix.entry(128 + dnp.function_code).or_default() += 1;
                profile.touch(ts_s);
                return Some(dst);
            }
            let profile = self.profiles.entry(src).or_insert_with(|| DeviceProfile::new(src));
            profile.responses += 1;
            profile.touch(ts_s);
            return Some(src);
        }
        let mb = parsed.modbus.as_ref()?;
        let (src, dst) = (parsed.src_ip?, parsed.dst_ip?);
        let ts_ms = parsed.timestamp_ms;
        let ts_s = ts_ms / 1000;
        if !mb.is_response {
            // A request: the server is the destination. Count the
            // poll, note the client, feed the rhythm, and remember
            // reads so their responses can be paired.
            let profile = self.profiles.entry(dst).or_insert_with(|| DeviceProfile::new(dst));
            profile.polls += 1;
            profile.clients.insert(src);
            if let Some(last) = profile.last_request_ms {
                let gap = ts_ms - last;
                if (0..MAX_POLL_GAP_MS).contains(&gap) {
                    profile.interval_sum_ms += gap;
                    profile.interval_count += 1;
                }
            }
            profile.last_request_ms = Some(ts_ms);
            profile.touch(ts_s);
            if (1..=4).contains(&mb.function_code) {
                if let (Some(address), Some(quantity)) = (mb.address, mb.quantity) {
                    if self.pending.len() >= MAX_PENDING {
                        self.pending.clear();
                    }
                    self.pending.insert(
                        (src, dst, mb.transaction_id),
                        PendingRead { function: mb.function_code, address, quantity },
                    );
                }
            }
            Some(dst)
        } else {
            // A response: the server is the source. Count it in the
            // mix, then pair it with its request to learn which
            // addresses the values belong to.
            let pending = self.pending.remove(&(dst, src, mb.transaction_id));
            let profile = self.profiles.entry(src).or_insert_with(|| DeviceProfile::new(src));
            profile.responses += 1;
            *profile.function_mix.entry(mb.function_code).or_default() += 1;
            profile.touch(ts_s);
            if !mb.is_exception {
                if let Some(pending) = pending {
                    let count = mb.values.len().min(pending.quantity as usize);
                    for i in 0..count {
                        let key = (pending.function, pending.address.wrapping_add(i as u16));
                        match profile.registers.get_mut(&key) {
                            Some(stat) => stat.observe(mb.values[i]),
                            None => {
                                if profile.registers.len() < MAX_REGISTERS_PER_DEVICE {
                                    let mut stat = RegisterStat::default();
                                    stat.observe(mb.values[i]);
                                    profile.registers.insert(key, stat);
                                }
                            }
                        }
                    }
                }
            }
            Some(src)
        }
    }

    /// One device's profile, if anything has been recorded.
    pub fn profile(&self, ip: IpAddr) -> Option<&DeviceProfile> {
        self.profiles.get(&ip)
    }

    /// All profiles, by device.
    pub fn profiles(&self) -> &HashMap<IpAddr, DeviceProfile> {
        &self.profiles
    }

    /// Loads a persisted profile (store hydration at open).
    pub fn insert_loaded(&mut self, profile: DeviceProfile) {
        self.profiles.insert(profile.ip, profile);
    }

    /// Forgets everything (data wipe).
    pub fn clear(&mut self) {
        self.profiles.clear();
        self.pending.clear();
    }
}

/// The function mix as one compact string, "3:120,4:55" — the
/// store's encoding (no JSON dependency in core).
pub fn mix_to_string(mix: &HashMap<u8, u64>) -> String {
    let mut entries: Vec<(&u8, &u64)> = mix.iter().collect();
    entries.sort_by_key(|(function, _)| **function);
    entries
        .iter()
        .map(|(function, count)| format!("{function}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Parses [`mix_to_string`]'s encoding back.
pub fn mix_from_str(text: &str) -> HashMap<u8, u64> {
    let mut mix = HashMap::new();
    for part in text.split(',') {
        if let Some((function, count)) = part.split_once(':') {
            if let (Ok(function), Ok(count)) = (function.parse::<u8>(), count.parse::<u64>()) {
                mix.insert(function, count);
            }
        }
    }
    mix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_packet;
    use crate::sim;
    use crate::source::Packet;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn a_poll_round_trip_builds_a_profile() {
        // HMI (10.0.2.10) reads 10 holding registers at 100 from
        // PLC1 (10.0.1.11); PLC1 answers 1000..=1009. Two rounds, a
        // second apart, so the rhythm has one gap to learn from.
        let mut recorder = ProfileRecorder::new();
        for round in 0..2i64 {
            let base_ms = 1_700_000_000_000 + round * 1000;
            let request = sim::build_modbus_read(
                "02:db:00:00:02:0a",
                "02:db:00:00:01:0b",
                [10, 0, 2, 10],
                [10, 0, 1, 11],
                40000,
                1,
                3,
                100,
                10,
                7,
            );
            let values: Vec<u16> = (0..10).map(|i| 1000 + i as u16 + (round as u16) * 100).collect();
            let response = sim::build_modbus_read_response(
                "02:db:00:00:01:0b",
                "02:db:00:00:02:0a",
                [10, 0, 1, 11],
                [10, 0, 2, 10],
                40000,
                1,
                3,
                &values,
                7,
            );
            for (offset, frame) in [(0, request), (40, response)] {
                let packet = Packet { timestamp_ms: base_ms + offset, data: frame };
                let parsed = parse_packet(&packet).unwrap();
                recorder.observe(&parsed);
            }
        }
        let profile = recorder.profile(ip(10, 0, 1, 11)).expect("PLC1 has a profile");
        assert_eq!(profile.polls, 2);
        assert_eq!(profile.responses, 2);
        assert_eq!(profile.function_mix.get(&3), Some(&2));
        assert!(profile.clients.contains(&ip(10, 0, 2, 10)));
        assert_eq!(profile.mean_poll_interval_ms(), Some(1000));
        let stat = profile.registers.get(&(3, 100)).expect("register 100 recorded");
        assert_eq!(stat.samples, 2);
        assert_eq!(stat.min, 1000);
        assert_eq!(stat.max, 1100);
        assert_eq!(stat.last, 1100);
        let stat = profile.registers.get(&(3, 109)).expect("register 109 recorded");
        assert_eq!(stat.last, 1109);
    }

    #[test]
    fn an_unpaired_response_counts_in_the_mix_but_teaches_no_registers() {
        // A response with no request seen first (the sensor started
        // mid-conversation): the mix learns, the registers cannot —
        // the response alone does not say which addresses it answers.
        let mut recorder = ProfileRecorder::new();
        let response = sim::build_modbus_read_response(
            "02:db:00:00:01:0b",
            "02:db:00:00:02:0a",
            [10, 0, 1, 11],
            [10, 0, 2, 10],
            40000,
            1,
            3,
            &[42, 43],
            9,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 1_700_000_000_000, data: response }).unwrap();
        recorder.observe(&parsed);
        let profile = recorder.profile(ip(10, 0, 1, 11)).unwrap();
        assert_eq!(profile.responses, 1);
        assert_eq!(profile.function_mix.get(&3), Some(&1));
        assert!(profile.registers.is_empty());
    }

    #[test]
    fn mix_encoding_round_trips() {
        let mut mix = HashMap::new();
        mix.insert(3u8, 120u64);
        mix.insert(4u8, 55u64);
        mix.insert(16u8, 2u64);
        assert_eq!(mix_to_string(&mix), "3:120,4:55,16:2");
        assert_eq!(mix_from_str("3:120,4:55,16:2"), mix);
        assert!(mix_from_str("").is_empty());
        assert!(mix_from_str("garbage").is_empty());
    }
}

#[cfg(test)]
mod dnp3_profile_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::parse::parse_packet;
    use crate::sim;
    use crate::source::Packet;

    #[test]
    fn dnp3_polls_build_a_profile() {
        let mut recorder = ProfileRecorder::default();
        for (i, at_ms) in [0i64, 2_000, 4_000].iter().enumerate() {
            let frame = sim::build_dnp3_poll(sim::RTU1, 100 + i as u32);
            let parsed = parse_packet(&Packet { timestamp_ms: *at_ms, data: frame }).unwrap();
            recorder.observe(&parsed);
        }
        let rtu = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 21));
        let profile = recorder.profiles.get(&rtu).expect("RTU profile");
        assert_eq!(profile.polls, 3);
        // DNP3 read (1) is namespaced at 128 + 1.
        assert_eq!(profile.function_mix.get(&129), Some(&3));
        assert_eq!(profile.mean_poll_interval_ms(), Some(2_000));
    }
}
