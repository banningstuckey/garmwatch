//! The pipeline: packet in → parse → inventory, connections, events →
//! store. This is the one path every traffic source flows through, so
//! the simulated plant, a replayed capture, and a live sensor are
//! indistinguishable to everything downstream.
//!
//! Phase 1 scope: discovery events for new devices and connections,
//! one event per Modbus command, quiet packet events for the rest.
//! Detection layers (Phase 4+) hook in after storage.

use crate::model::{Connection, Device, Event, EventKind, Protocol};
use crate::parse::{parse_packet, ParsedPacket};
use crate::source::Packet;
use crate::store::Store;
use std::net::IpAddr;

/// Processes one raw packet end to end, storing everything it learns.
/// Returns the events it produced (already stored, ids set) so the UI
/// can stream them live. Unparseable packets produce no events —
/// Phase 3 decides what to do with genuinely broken traffic.
pub fn process_packet(store: &Store, packet: &Packet) -> Vec<Event> {
    let parsed = match parse_packet(packet) {
        Ok(parsed) => parsed,
        Err(_) => return Vec::new(),
    };
    // Behavior recording (feature program): every Modbus answer
    // feeds the responding device's profile — the twin's feedstock.
    store.record_packet_profile(&parsed);
    let timestamp_s = parsed.timestamp_ms / 1000;
    let mut events = Vec::new();

    // Device discovery: any endpoint never seen before joins the
    // inventory and raises a discovery event.
    for ip in [parsed.src_ip, parsed.dst_ip].into_iter().flatten() {
        if !store.device_exists(ip).unwrap_or(true) {
            let _ = store.add_device(&Device::new(ip, timestamp_s));
            let mut event = Event::new(
                timestamp_s,
                EventKind::DeviceDiscovered,
                format!("New device seen: {ip}"),
            );
            event.src_ip = Some(ip);
            events.push(event);
        }
    }

    let (src_ip, dst_ip) = match (parsed.src_ip, parsed.dst_ip) {
        (Some(src), Some(dst)) => (src, dst),
        _ => return finish(store, events),
    };

    // Connection accounting. Modbus responses are folded back into the
    // client's conversation (client → server), so a poll and its reply
    // are one connection, not two.
    let is_response = parsed.modbus.as_ref().map(|mb| mb.is_response).unwrap_or(false);
    let (client, server, server_port) = if is_response {
        (dst_ip, src_ip, parsed.src_port.unwrap_or(0))
    } else {
        (src_ip, dst_ip, parsed.dst_port.unwrap_or(0))
    };
    let connection = Connection {
        id: None,
        src_ip: client,
        dst_ip: server,
        dst_port: server_port,
        protocol: parsed.protocol,
        first_seen: timestamp_s,
        last_seen: timestamp_s,
        packet_count: 1,
        byte_count: parsed.length as u64,
    };
    if let Ok(true) = store.record_connection(&connection) {
        let mut event = Event::new(
            timestamp_s,
            EventKind::ConnectionObserved,
            format!(
                "New connection: {} → {}:{} ({})",
                name_of(store, client),
                name_of(store, server),
                server_port,
                parsed.protocol.as_tag(),
            ),
        );
        event.src_ip = Some(client);
        event.dst_ip = Some(server);
        events.push(event);
    }

    // The headline event for this packet.
    events.push(packet_event(store, &parsed, src_ip, dst_ip, timestamp_s));
    finish(store, events)
}

/// [`process_packet`], plus the rules layer: alerts raised on this
/// packet are converted to alert events, stored, and returned with
/// the packet's own events (alerts last). The rules layer keeps its
/// session state (baseline, dedup) in the caller's hands, so each
/// feed — simulation, replay, scenario, future live capture — owns
/// one, constructed via [`crate::detect::RulesLayer::from_store`].
pub fn process_packet_with_rules(
    store: &Store,
    packet: &Packet,
    rules: &mut crate::detect::RulesLayer,
) -> Vec<Event> {
    let mut events = process_packet(store, packet);
    let alerts = rules.observe_packet(store, packet, &events);
    append_alerts(store, packet, alerts, &mut events, false);
    events
}

/// The full detection stack: rules (per packet) plus the anomaly
/// layer (per chunk — its alerts surface when a chunk closes). This
/// is what the app's feeds run.
///
/// `maintenance` is the maintenance window: while it is open, the
/// anomaly layer is paused (the traffic neither teaches it nor
/// alerts it — an engineer's legitimate work is not an attack, and
/// their laptop must not become "normal"), and every alert the
/// rules still raise is stored with a "Maintenance window:" prefix
/// so the log shows it in context and the UI can keep it out of the
/// alert badge. Nothing is hidden: the window's traffic is all in
/// the log, marked.
pub fn process_packet_full(
    store: &Store,
    packet: &Packet,
    rules: &mut crate::detect::RulesLayer,
    anomaly: &mut crate::detect::AnomalyLayer,
    maintenance: bool,
) -> Vec<Event> {
    anomaly.paused = maintenance;
    let mut events = process_packet(store, packet);
    let rule_alerts = rules.observe_packet(store, packet, &events);
    append_alerts(store, packet, rule_alerts, &mut events, maintenance);
    let anomaly_alerts = anomaly.observe_packet(store, packet, &events);
    append_alerts(store, packet, anomaly_alerts, &mut events, maintenance);
    events
}

/// Converts detection alerts to stored alert events on the packet's
/// event list: "[rule] Title — detail" as the summary, the alert's
/// subject device as the source.
fn append_alerts(
    store: &Store,
    packet: &Packet,
    alerts: Vec<crate::detect::Alert>,
    events: &mut Vec<Event>,
    maintenance: bool,
) {
    if alerts.is_empty() {
        return;
    }
    let parsed = parse_packet(packet).ok();
    let alert_events: Vec<Event> = alerts
        .iter()
        .map(|alert| {
            let mut event = Event::new(
                alert.timestamp,
                EventKind::AlertRaised,
                if maintenance {
                    format!("Maintenance window: {} — {}", alert.title, alert.detail)
                } else {
                    format!("{} — {}", alert.title, alert.detail)
                },
            );
            event.src_ip = alert.device_ip;
            event.dst_ip = parsed.as_ref().and_then(|p| p.dst_ip);
            event
        })
        .collect();
    events.extend(finish(store, alert_events));
}

/// Builds the per-packet event: Modbus commands get the full sentence,
/// responses and plain traffic get a quieter one.
fn packet_event(
    store: &Store,
    parsed: &ParsedPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timestamp_s: i64,
) -> Event {
    let src = name_of(store, src_ip);
    let dst = name_of(store, dst_ip);
    let (kind, summary) = if let Some(dnp) = &parsed.dnp3 {
        if dnp.is_response {
            (
                EventKind::PacketObserved,
                format!(
                    "{src} \u{2192} {dst}: DNP3 {} response{}",
                    dnp.function_name(),
                    if dnp.is_unsolicited { " (unsolicited)" } else { "" },
                ),
            )
        } else {
            (
                EventKind::Dnp3Command { function_code: dnp.function_code, is_write: dnp.is_control },
                format!(
                    "{src} \u{2192} {dst}: {}DNP3 {}{}{}",
                    if dnp.is_control { "WRITE \u{2014} " } else { "" },
                    dnp.function_name(),
                    if dnp.control_object { " (control output)" } else { "" },
                    if !dnp.crc_ok { " [bad checksum]" } else { "" },
                ),
            )
        }
    } else {
    match &parsed.modbus {
        Some(mb) if mb.is_response => (
            EventKind::PacketObserved,
            format!(
                "{src} → {dst}: {} response{}",
                mb.function_name(),
                if mb.is_exception { " (exception!)" } else { "" },
            ),
        ),
        Some(mb) => {
            let detail = match (mb.address, mb.quantity, mb.value) {
                (Some(addr), Some(qty), _) => format!("@ {addr} × {qty}"),
                (Some(addr), _, Some(value)) => format!("@ {addr} = {value}"),
                _ => String::new(),
            };
            (
                EventKind::ModbusCommand { function_code: mb.function_code, is_write: mb.is_write },
                format!(
                    "{src} → {dst}: {}{} {detail}",
                    if mb.is_write { "WRITE — " } else { "" },
                    mb.function_name(),
                ),
            )
        }
        None => (
            EventKind::PacketObserved,
            format!(
                "{src} → {dst}: {}/{} ({} bytes)",
                match parsed.protocol {
                    Protocol::Udp => "UDP",
                    _ => "TCP",
                },
                parsed.dst_port.unwrap_or(0),
                parsed.length,
            ),
        ),
    }
    };
    let mut event = Event::new(timestamp_s, kind, summary);
    event.src_ip = Some(src_ip);
    event.dst_ip = Some(dst_ip);
    event
}

/// Stores the events and returns them with ids assigned.
fn finish(store: &Store, mut events: Vec<Event>) -> Vec<Event> {
    for event in &mut events {
        if let Ok(id) = store.record_event(event) {
            event.id = Some(id);
        }
    }
    events
}

/// Human name for an IP: the inventory label when known
/// ("Line 1 PLC"), else the bare address. With a handful of devices,
/// reading the inventory per packet is fine; Phase 3 can cache.
fn name_of(store: &Store, ip: IpAddr) -> String {
    match store.list_devices() {
        Ok(devices) => devices
            .iter()
            .find(|device| device.ip == ip)
            .and_then(|device| device.label.clone())
            .unwrap_or_else(|| ip.to_string()),
        Err(_) => ip.to_string(),
    }
}

/// Snapshot of what the pipeline has accumulated, for status displays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub devices: i64,
    pub events: i64,
}

pub fn stats(store: &Store) -> PipelineStats {
    PipelineStats {
        devices: store.device_count().unwrap_or(0),
        events: store.event_count().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_corrupt_dnp3_frame_raises_the_checksum_rule() {
        let store = Store::open_in_memory().unwrap();
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut rules = crate::detect::RulesLayer::default();
        let mut anomaly = crate::detect::AnomalyLayer::default();
        let mut frame = sim::build_dnp3_poll(sim::RTU1, 42);
        // Flip a byte inside the application area (after the
        // Ethernet/IP/TCP headers and the 10-byte DNP3 header):
        // the frame still parses, but its block CRC now fails.
        let at = frame.len() - 4;
        frame[at] ^= 0xFF;
        let packet = Packet { timestamp_ms: 1_700_000_000_000, data: frame };
        let events = process_packet_full(&store, &packet, &mut rules, &mut anomaly, false);
        assert!(
            events.iter().any(|e| e.kind == EventKind::AlertRaised && e.summary.contains("[dnp3-bad-crc]")),
            "alerts: {:?}",
            events.iter().map(|e| &e.summary).collect::<Vec<_>>()
        );
    }

    use super::*;
    use crate::sim;
    use crate::source::{SimulatedSource, TrafficSource};

    #[test]
    fn simulated_plant_flows_through_the_pipeline() {
        let store = Store::open_in_memory().unwrap();
        // Pre-register the roster, as the app shell does at startup:
        // discovery then has ground truth to name.
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut source = SimulatedSource::new(1_700_000_000_000);
        let mut modbus_commands = 0;
        let mut writes = 0;
        for _ in 0..300 {
            let packet = source.next_packet().unwrap();
            for event in process_packet(&store, &packet) {
                match event.kind {
                    EventKind::ModbusCommand { is_write, .. } => {
                        modbus_commands += 1;
                        if is_write {
                            writes += 1;
                            assert!(event.summary.contains("Operator HMI"), "{}", event.summary);
                        }
                    }
                    _ => {}
                }
            }
        }
        let stats = stats(&store);
        assert_eq!(stats.devices, 8);
        assert!(stats.events > 250, "events stored: {}", stats.events);
        assert!(modbus_commands > 50, "commands seen: {modbus_commands}");
        assert!(writes >= 1, "at least one setpoint write in 300 packets");
    }

    #[test]
    fn normal_plant_traffic_raises_no_alerts() {
        // The false-positive discipline: 400 packets of ordinary plant
        // operation, rules armed, must produce zero alerts.
        let store = Store::open_in_memory().unwrap();
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut rules = crate::detect::RulesLayer::new();
        let mut source = SimulatedSource::new(1_700_000_000_000);
        let mut alerts = 0;
        for _ in 0..400 {
            let packet = source.next_packet().unwrap();
            for event in process_packet_with_rules(&store, &packet, &mut rules) {
                if event.kind == EventKind::AlertRaised {
                    alerts += 1;
                }
            }
        }
        assert_eq!(alerts, 0, "normal traffic must never alert");
        assert!(rules.baseline_sealed(), "baseline seals during the run");
    }

    #[test]
    fn sample_replay_flags_the_laptop() {
        // The Phase 3 sample was bait; the rules are the trap. The
        // foreign laptop must be flagged for writing, and every one of
        // the nine foreign devices announced as new.
        let store = Store::open_in_memory().unwrap();
        let mut rules = crate::detect::RulesLayer::new();
        let mut new_devices = 0;
        let mut laptop_write_alerts = 0;
        for packet in crate::sample::sample_packets() {
            for event in process_packet_with_rules(&store, &packet, &mut rules) {
                if event.kind == EventKind::AlertRaised {
                    if event.summary.contains("[new-device]") {
                        new_devices += 1;
                    }
                    if event.summary.contains("192.168.50.77")
                        && (event.summary.contains("[write-from-non-hmi]")
                            || event.summary.contains("[write-outside-pattern]"))
                    {
                        laptop_write_alerts += 1;
                    }
                }
            }
        }
        assert_eq!(new_devices, 9, "all nine foreign devices announced");
        assert_eq!(laptop_write_alerts, 2, "the laptop's write trips rules 3 and 7");
    }

    #[test]
    fn anomaly_layer_stays_quiet_on_normal_traffic() {
        // 2,000 packets ≈ 13 chunks: learning completes mid-run and
        // the trained layer must still find ordinary operation boring.
        let store = Store::open_in_memory().unwrap();
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut rules = crate::detect::RulesLayer::new();
        let mut anomaly = crate::detect::AnomalyLayer::new();
        let mut source = SimulatedSource::new(1_700_000_000_000);
        let mut warnings = 0;
        for _ in 0..2000 {
            let packet = source.next_packet().unwrap();
            for event in process_packet_full(&store, &packet, &mut rules, &mut anomaly, false) {
                if event.summary.contains("[early-warning]") {
                    warnings += 1;
                }
            }
        }
        assert_eq!(warnings, 0, "normal traffic must not raise early warnings");
        assert!(!anomaly.learning, "trained after 13 chunks");
        assert!(anomaly.status().risk_score < 50, "risk stays low: {}", anomaly.status().risk_score);
    }

    #[test]
    fn maintenance_window_pauses_learning_and_marks_alerts() {
        // Learning pause: 2,000 packets inside a window teach the
        // anomaly layer nothing; the same traffic outside the window
        // trains it.
        let store = Store::open_in_memory().unwrap();
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut rules = crate::detect::RulesLayer::new();
        let mut anomaly = crate::detect::AnomalyLayer::new();
        let mut source = SimulatedSource::new(1_700_000_000_000);
        for _ in 0..2000 {
            let packet = source.next_packet().unwrap();
            process_packet_full(&store, &packet, &mut rules, &mut anomaly, true);
        }
        assert!(anomaly.learning, "a window's traffic must not train the layer");
        assert_eq!(anomaly.status().risk_score, 0, "no scoring inside a window");
        let mut source = SimulatedSource::new(1_700_100_000_000);
        for _ in 0..2000 {
            let packet = source.next_packet().unwrap();
            process_packet_full(&store, &packet, &mut rules, &mut anomaly, false);
        }
        assert!(!anomaly.learning, "the same traffic outside a window trains it");

        // Marking: the sample laptop's write alerts carry the prefix
        // inside a window, and not outside one.
        for maintenance in [true, false] {
            let store = Store::open_in_memory().unwrap();
            let mut rules = crate::detect::RulesLayer::new();
            let mut anomaly = crate::detect::AnomalyLayer::new();
            let mut marked = 0;
            let mut unmarked = 0;
            for packet in crate::sample::sample_packets() {
                for event in process_packet_full(&store, &packet, &mut rules, &mut anomaly, maintenance) {
                    if event.kind == EventKind::AlertRaised {
                        if event.summary.starts_with("Maintenance window: ") {
                            marked += 1;
                        } else {
                            unmarked += 1;
                        }
                    }
                }
            }
            if maintenance {
                assert!(marked > 0, "window alerts are marked");
                assert_eq!(unmarked, 0, "no unmarked alerts inside a window");
            } else {
                assert_eq!(marked, 0, "no window marks outside a window");
                assert!(unmarked > 0, "the sample still alerts outside a window");
            }
        }
    }

    #[test]
    fn threat_intel_address_alerts() {
        let store = Store::open_in_memory().unwrap();
        let mut rules = crate::detect::RulesLayer::new();
        let frame = sim::build_tcp_frame(
            "02:db:00:00:04:0a",
            "02:db:00:00:03:20",
            [10, 0, 4, 10],
            [203, 0, 113, 66],
            51000,
            443,
            b"beacon",
            1,
        );
        let events = process_packet_with_rules(
            &store,
            &Packet { timestamp_ms: 60_000, data: frame },
            &mut rules,
        );
        assert!(
            events.iter().any(|e| e.summary.contains("[threat-intel]")),
            "{events:?}"
        );
    }

    #[test]
    fn unknown_device_is_discovered_from_traffic() {
        let store = Store::open_in_memory().unwrap();
        let frame = sim::build_tcp_frame(
            "02:db:00:00:09:09",
            "02:db:00:00:03:20",
            [10, 9, 9, 9],
            [10, 0, 3, 20],
            51000,
            443,
            b"ping",
            1,
        );
        let events = process_packet(&store, &Packet { timestamp_ms: 60_000, data: frame });
        assert!(events.iter().any(|e| e.kind == EventKind::DeviceDiscovered));
        assert!(store.device_exists("10.9.9.9".parse().unwrap()).unwrap());
    }
}

