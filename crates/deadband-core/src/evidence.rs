//! One-click audit evidence: a printable report over the
//! universal audit trail, shaped for the questions an auditor
//! (NERC CIP, IEC 62443, an insurer, an investigator) actually
//! asks — what happened, who did what, who vouched for the actor
//! that later misbehaved, and what is being held right now.
//!
//! The report is a view, never an edit: building one changes
//! nothing in the trail (the *shell* records the pull itself as
//! an operator action before building — the meta-audit rule — so
//! the report even contains the record of its own generation).
//!
//! Rendering produces a self-contained HTML fragment with its
//! own scoped styles: it prints cleanly from the app and can be
//! saved as evidence as-is. Per the record-security rules, an
//! exported report is also an out-of-band anchor — a point in
//! history that lives somewhere the sensor doesn't.

use crate::model::{Event, EventKind};
use crate::suspicion;
use std::collections::HashMap;
use std::net::IpAddr;

/// One timestamped line of the report.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceRow {
    pub at_s: i64,
    pub summary: String,
}

/// One Ignore, with its outcome: what the actor did afterwards.
#[derive(Debug, Clone, PartialEq)]
pub struct VouchFinding {
    pub ip: IpAddr,
    pub ignored_by: String,
    pub at_s: i64,
    /// Alerts about this actor recorded after the Ignore.
    pub later_alerts: usize,
    /// The heaviest suspicion weight among those later alerts.
    pub worst_points: i32,
}

/// The whole report, as data (the HTML renderer is a view of it).
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceReport {
    pub generated_at_s: i64,
    pub window_start_s: i64,
    pub event_count: usize,
    pub alert_count: usize,
    pub operator_action_count: usize,
    pub canary_touches: usize,
    pub new_device_count: usize,
    /// Every operator action in the window, oldest first — the
    /// audit trail proper.
    pub operator_actions: Vec<EvidenceRow>,
    /// Every alert in the window, oldest first.
    pub alerts: Vec<EvidenceRow>,
    /// Every Ignore in the window, with what happened next.
    pub vouches: Vec<VouchFinding>,
    /// Actors currently held in quarantine: (ip, by, at).
    pub held: Vec<(IpAddr, String, i64)>,
}

/// Builds the report from events at or after `window_start_s`
/// (any order; they are sorted here) plus the live quarantine
/// table.
pub fn build_report(
    events: &[Event],
    quarantined: &HashMap<IpAddr, (String, i64)>,
    window_start_s: i64,
    generated_at_s: i64,
) -> EvidenceReport {
    let mut sorted: Vec<&Event> = events.iter().filter(|e| e.timestamp >= window_start_s).collect();
    sorted.sort_by_key(|e| (e.timestamp, e.id.unwrap_or(0)));
    let mut report = EvidenceReport {
        generated_at_s,
        window_start_s,
        event_count: sorted.len(),
        alert_count: 0,
        operator_action_count: 0,
        canary_touches: 0,
        new_device_count: 0,
        operator_actions: Vec::new(),
        alerts: Vec::new(),
        vouches: Vec::new(),
        held: Vec::new(),
    };
    for event in &sorted {
        match event.kind {
            EventKind::AlertRaised => {
                report.alert_count += 1;
                if event.summary.contains("Canary PLC touched") {
                    report.canary_touches += 1;
                }
                report.alerts.push(EvidenceRow { at_s: event.timestamp, summary: event.summary.clone() });
            }
            EventKind::OperatorAction => {
                report.operator_action_count += 1;
                report
                    .operator_actions
                    .push(EvidenceRow { at_s: event.timestamp, summary: event.summary.clone() });
            }
            EventKind::DeviceDiscovered => report.new_device_count += 1,
            _ => {}
        }
    }
    // Vouches: every Ignore, followed forward. An actor that
    // stayed quiet is a clean vouch; one that alerted afterwards
    // is the row an investigator reads first.
    for event in &sorted {
        if event.kind != EventKind::OperatorAction {
            continue;
        }
        if let Some((ip, mark)) = suspicion::parse_ignore(event) {
            let mut later_alerts = 0;
            let mut worst_points = 0;
            for other in &sorted {
                if other.kind == EventKind::AlertRaised
                    && other.timestamp > event.timestamp
                    && other.src_ip == Some(ip)
                {
                    later_alerts += 1;
                    if let Some(points) = suspicion::base_points(&other.summary) {
                        worst_points = worst_points.max(points);
                    }
                }
            }
            report.vouches.push(VouchFinding {
                ip,
                ignored_by: mark.user,
                at_s: event.timestamp,
                later_alerts,
                worst_points,
            });
        }
    }
    let mut held: Vec<(IpAddr, String, i64)> = quarantined
        .iter()
        .map(|(ip, (by, at))| (*ip, by.clone(), *at))
        .collect();
    held.sort_by_key(|(ip, _, _)| ip.to_string());
    report.held = held;
    report
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Formats Unix seconds as "YYYY-MM-DD HH:MM:SS UTC" without a
/// date library (civil-from-days conversion, after Howard
/// Hinnant's algorithm).
pub fn format_ts(ts_s: i64) -> String {
    let days = ts_s.div_euclid(86_400);
    let secs = ts_s.rem_euclid(86_400);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// Renders the report as a self-contained HTML fragment (scoped
/// styles under `.ev-`) ready to drop into the app's evidence
/// view or save as a standalone evidence page.
pub fn render_html(report: &EvidenceReport, generated_by: &str) -> String {
    let mut out = String::new();
    out.push_str(
        "<style>\
         .ev-doc{font:14px/1.5 system-ui,sans-serif;max-width:820px}\
         .ev-doc h2{margin:0 0 2px}.ev-doc h3{margin:22px 0 6px}\
         .ev-doc table{border-collapse:collapse;width:100%}\
         .ev-doc td,.ev-doc th{border:1px solid #999;padding:4px 8px;text-align:left;vertical-align:top}\
         .ev-doc .ev-meta{opacity:.75}.ev-doc .ev-flag{font-weight:700}\
         </style><div class=\"ev-doc\">",
    );
    out.push_str("<h2>GarmWatch — audit evidence report</h2>");
    out.push_str(&format!(
        "<p class=\"ev-meta\">Generated {} by {} · Window: everything stored since {} · \
         {} events · {} alerts · {} operator actions · {} canary touches · {} new devices</p>",
        format_ts(report.generated_at_s),
        escape(generated_by),
        format_ts(report.window_start_s),
        report.event_count,
        report.alert_count,
        report.operator_action_count,
        report.canary_touches,
        report.new_device_count,
    ));
    out.push_str("<h3>Held in quarantine now</h3>");
    if report.held.is_empty() {
        out.push_str("<p>No actor is currently held.</p>");
    } else {
        out.push_str("<table><tr><th>Actor</th><th>Ordered by</th><th>Since</th></tr>");
        for (ip, by, at) in &report.held {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                ip,
                escape(by),
                format_ts(*at)
            ));
        }
        out.push_str("</table>");
    }
    out.push_str("<h3>Ignores (vouches) and what happened after</h3>");
    if report.vouches.is_empty() {
        out.push_str("<p>No actor was ignored in this window.</p>");
    } else {
        out.push_str(
            "<table><tr><th>When</th><th>Actor</th><th>Ignored by</th><th>Alerts afterwards</th></tr>",
        );
        for vouch in &report.vouches {
            let outcome = if vouch.later_alerts == 0 {
                "none — the actor stayed quiet".to_string()
            } else {
                format!(
                    "<span class=\"ev-flag\">{} (heaviest signal: {} pts)</span>",
                    vouch.later_alerts, vouch.worst_points
                )
            };
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                format_ts(vouch.at_s),
                vouch.ip,
                escape(&vouch.ignored_by),
                outcome
            ));
        }
        out.push_str("</table>");
    }
    out.push_str("<h3>Operator actions — the audit trail</h3>");
    if report.operator_actions.is_empty() {
        out.push_str("<p>No operator actions in this window.</p>");
    } else {
        out.push_str("<table><tr><th>When</th><th>Action</th></tr>");
        for row in &report.operator_actions {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                format_ts(row.at_s),
                escape(&row.summary)
            ));
        }
        out.push_str("</table>");
    }
    out.push_str("<h3>Alerts</h3>");
    if report.alerts.is_empty() {
        out.push_str("<p>No alerts in this window.</p>");
    } else {
        out.push_str("<table><tr><th>When</th><th>Alert</th></tr>");
        for row in &report.alerts {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                format_ts(row.at_s),
                escape(&row.summary)
            ));
        }
        out.push_str("</table>");
    }
    out.push_str(
        "<p class=\"ev-meta\">This report is a view over GarmWatch's stored audit trail, \
         generated on the sensor. Generating it was itself recorded in the trail. \
         GarmWatch is passive: it observes and records; it does not act on the network.</p></div>",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn event(at: i64, kind: EventKind, summary: &str, src: Option<IpAddr>) -> Event {
        let mut e = Event::new(at, kind, summary.to_string());
        e.src_ip = src;
        e
    }

    #[test]
    fn timestamps_format_in_utc() {
        assert_eq!(format_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_ts(1_763_510_400), "2025-11-19 00:00:00 UTC");
        assert_eq!(format_ts(1_763_553_600), "2025-11-19 12:00:00 UTC");
    }

    #[test]
    fn a_report_counts_and_follows_vouches() {
        let rogue = ip(10, 0, 9, 77);
        let events = vec![
            event(1_000, EventKind::DeviceDiscovered, "New device", Some(rogue)),
            event(
                2_000,
                EventKind::OperatorAction,
                "Ignored actor 10.0.9.77 — marked known/expected by banning. GarmWatch keeps watching.",
                None,
            ),
            event(
                3_000,
                EventKind::AlertRaised,
                "[write-from-non-hmi] Rogue wrote to PLC",
                Some(rogue),
            ),
            event(
                3_500,
                EventKind::AlertRaised,
                "Canary PLC touched — 10.0.9.77 read (FC3). Nothing legitimate talks to the canary: this is an intruder.",
                Some(rogue),
            ),
            event(4_000, EventKind::OperatorAction, "Maintenance window started by banning — 60 minutes.", None),
        ];
        let mut held = HashMap::new();
        held.insert(rogue, ("banning".to_string(), 5_000));
        let report = build_report(&events, &held, 0, 6_000);
        assert_eq!(report.event_count, 5);
        assert_eq!(report.alert_count, 2);
        assert_eq!(report.operator_action_count, 2);
        assert_eq!(report.canary_touches, 1);
        assert_eq!(report.new_device_count, 1);
        assert_eq!(report.vouches.len(), 1);
        let vouch = &report.vouches[0];
        assert_eq!(vouch.ignored_by, "banning");
        assert_eq!(vouch.later_alerts, 2);
        assert_eq!(vouch.worst_points, 40);
        assert_eq!(report.held.len(), 1);
        let html = render_html(&report, "banning on sensor-1");
        assert!(html.contains("audit evidence report"));
        assert!(html.contains("heaviest signal: 40 pts"));
        assert!(html.contains("Maintenance window started"));
    }

    #[test]
    fn html_escapes_summaries() {
        let events = vec![event(10, EventKind::OperatorAction, "User <script>alert(1)</script> did a thing", None)];
        let report = build_report(&events, &HashMap::new(), 0, 20);
        let html = render_html(&report, "tester");
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
