//! Daily triage (feature program): the whole day, ranked, in
//! plain English.
//!
//! An operator should not have to read hundreds of log lines to
//! learn what needs their eyes. The triage report reads the last
//! 24 hours the way the suspicion layer does — from the stored
//! event log — and ranks what matters into a short list:
//!
//! 1. Canary touches. Always first: there is no innocent version.
//! 2. Actors sitting in quarantine, waiting on a human decision.
//! 3. The highest suspicion scores, with their top reason.
//! 4. Ignores issued — who vouched for whom is investigation data,
//!    and the day it happens is the day to see it.
//! 5. Maintenance windows opened, and new devices seen.
//!
//! The list is deterministic — the same day always produces the
//! same triage. The local AI analyst can then be pointed at the
//! whole report for a prose brief ("Explain today"), under the
//! same house rules as incident briefs: facts only, plain English,
//! never claim a confirmed attack, never direct a response.

use crate::model::{Event, EventKind};
use crate::suspicion::{parse_ignore, Suspicion, WINDOW_S};
use std::collections::HashMap;
use std::net::IpAddr;

/// One line of the morning briefing.
#[derive(Debug, Clone, PartialEq)]
pub struct TriageItem {
    /// The headline — what needs eyes, in one line.
    pub headline: String,
    /// The plain-English follow-through.
    pub detail: String,
    /// The actor involved, when singular.
    pub ip: Option<IpAddr>,
    /// The actor's suspicion score, when relevant.
    pub score: Option<i32>,
}

/// The day's briefing: ranked items plus the raw counts.
#[derive(Debug, Clone, PartialEq)]
pub struct TriageReport {
    /// When the report was generated, Unix seconds.
    pub generated_at_s: i64,
    /// Start of the window the report covers, Unix seconds.
    pub window_start_s: i64,
    /// The ranked items (at most 6; exactly 1 on a quiet day).
    pub items: Vec<TriageItem>,
    /// Alert events in the window.
    pub alert_count: usize,
    /// All events in the window (as fetched; the fetch is capped).
    pub event_count: usize,
    /// Devices first seen in the window.
    pub new_device_count: usize,
    /// Canary touches in the window.
    pub canary_touches: usize,
    /// Operator actions in the window.
    pub operator_action_count: usize,
}

/// How an actor is named in the briefing: its label when it has
/// one ("PLC1 (10.0.1.11)"), else its address.
fn name_of(names: &HashMap<IpAddr, String>, ip: IpAddr) -> String {
    names.get(&ip).cloned().unwrap_or_else(|| ip.to_string())
}

/// Builds the report. `events` should cover the last [`WINDOW_S`]
/// seconds; `scores` and `quarantined` come from the suspicion
/// layer and the store; `names` maps devices to display names.
pub fn daily_report(
    events: &[Event],
    scores: &HashMap<IpAddr, Suspicion>,
    quarantined: &HashMap<IpAddr, (String, i64)>,
    names: &HashMap<IpAddr, String>,
    now_s: i64,
) -> TriageReport {
    let window_start = now_s - WINDOW_S;
    let in_window: Vec<&Event> = events.iter().filter(|e| e.timestamp >= window_start).collect();

    let alert_count = in_window.iter().filter(|e| e.kind == EventKind::AlertRaised).count();
    let operator_action_count =
        in_window.iter().filter(|e| e.kind == EventKind::OperatorAction).count();
    let new_devices: Vec<IpAddr> = in_window
        .iter()
        .filter(|e| e.kind == EventKind::DeviceDiscovered)
        .filter_map(|e| e.src_ip)
        .collect();
    let canary_events: Vec<&&Event> = in_window
        .iter()
        .filter(|e| e.kind == EventKind::AlertRaised && e.summary.contains("Canary PLC touched"))
        .collect();

    let mut items: Vec<TriageItem> = Vec::new();

    // 1. The canary — always first, never buried.
    if let Some(latest) = canary_events.iter().max_by_key(|e| e.timestamp) {
        let visitor = latest.src_ip;
        items.push(TriageItem {
            headline: format!(
                "Canary PLC touched {} time{} — most recently by {}",
                canary_events.len(),
                if canary_events.len() == 1 { "" } else { "s" },
                visitor.map(|ip| name_of(names, ip)).unwrap_or_else(|| "an unknown device".to_string()),
            ),
            detail: "Nothing legitimate talks to the canary. Treat the visitor as an intruder until an investigation says otherwise.".to_string(),
            ip: visitor,
            score: visitor.and_then(|ip| scores.get(&ip)).map(|s| s.score),
        });
    }

    // 2. Whoever is sitting in quarantine is waiting on a human.
    let mut held: Vec<(&IpAddr, &(String, i64))> = quarantined.iter().collect();
    held.sort_by_key(|(ip, _)| std::cmp::Reverse(scores.get(ip).map(|s| s.score).unwrap_or(0)));
    for (ip, (user, _)) in held {
        items.push(TriageItem {
            headline: format!("{} is in quarantine (ordered by {user})", name_of(names, *ip)),
            detail: "Still held out of production. Release it from its device detail when the investigation is done — or leave it held; there is no clock on a quarantine.".to_string(),
            ip: Some(*ip),
            score: scores.get(ip).map(|s| s.score),
        });
    }

    // 3. The top suspicion scores that are not already listed.
    let listed: Vec<IpAddr> = items.iter().filter_map(|item| item.ip).collect();
    let mut top: Vec<(&IpAddr, &Suspicion)> =
        scores.iter().filter(|(_, s)| s.score >= 25).collect();
    top.sort_by_key(|(_, s)| std::cmp::Reverse(s.score));
    for (ip, suspicion) in top.into_iter().filter(|(ip, _)| !listed.contains(ip)).take(3) {
        let reason = suspicion
            .factors
            .iter()
            .find(|(_, points)| *points > 0)
            .map(|(text, points)| format!("{text} (+{points})"))
            .unwrap_or_else(|| "Several smaller signals added up.".to_string());
        items.push(TriageItem {
            headline: format!("{} — suspicion {}%", name_of(names, *ip), suspicion.score),
            detail: format!("Top reason: {reason}. Open the device for the full why, and to Ignore or Quarantine it."),
            ip: Some(*ip),
            score: Some(suspicion.score),
        });
    }

    // 4. Ignores issued — vouches are investigation data.
    let mut vouches: Vec<String> = Vec::new();
    for event in &in_window {
        if event.kind == EventKind::OperatorAction {
            if let Some((ip, mark)) = parse_ignore(event) {
                vouches.push(format!("{} by {}", name_of(names, ip), mark.user));
            }
        }
    }
    if !vouches.is_empty() {
        items.push(TriageItem {
            headline: format!("{} actor{} vouched for (Ignore) in the last day", vouches.len(), if vouches.len() == 1 { "" } else { "s" }),
            detail: format!("{} — an Ignore halves earlier signals; it never stops the watching, and the vouch itself is on the record.", vouches.join("; ")),
            ip: None,
            score: None,
        });
    }

    // 5. Maintenance windows + new devices, when there is room.
    let windows = in_window
        .iter()
        .filter(|e| e.kind == EventKind::OperatorAction && e.summary.starts_with("Maintenance window started"))
        .count();
    if windows > 0 {
        items.push(TriageItem {
            headline: format!("{windows} maintenance window{} opened", if windows == 1 { "" } else { "s" }),
            detail: "Windows pause anomaly learning, and their alerts are marked in the log. If a window was opened and nobody remembers opening it, that is worth a question.".to_string(),
            ip: None,
            score: None,
        });
    }
    if !new_devices.is_empty() && items.len() < 6 {
        items.push(TriageItem {
            headline: format!("{} new device{} seen", new_devices.len(), if new_devices.len() == 1 { "" } else { "s" }),
            detail: "New devices land unplaced in Assets with a suggested placement to confirm. A device nobody can account for is a finding, not a nuisance.".to_string(),
            ip: None,
            score: None,
        });
    }

    items.truncate(6);
    if items.is_empty() {
        items.push(TriageItem {
            headline: "Nothing needs your eyes".to_string(),
            detail: format!(
                "No alerts, no canary touches, no new devices in the last day — {alert_count} alerts and {} events, all routine. Days like this are the baseline doing its job.",
                in_window.len(),
            ),
            ip: None,
            score: None,
        });
    }

    TriageReport {
        generated_at_s: now_s,
        window_start_s: window_start,
        items,
        alert_count,
        event_count: in_window.len(),
        new_device_count: new_devices.len(),
        canary_touches: canary_events.len(),
        operator_action_count,
    }
}

/// The analyst prompt for a whole day's triage — same house rules
/// as the incident brief, pointed at the ranked list instead of a
/// single alert.
pub fn build_triage_prompt(report: &TriageReport) -> String {
    let mut prompt = String::new();
    prompt.push_str(
        "You are the analyst inside GarmWatch, a passive OT (industrial control) network \
         monitor. Below is the daily triage for the last 24 hours: the ranked list of \
         what most needs a plant operator's attention, with counts. Write a short daily \
         brief for an operator who is not a security specialist.\n\n\
         Use exactly three short sections with these headings:\n\
         The day in brief\nCheck first\nCan probably wait\n\n\
         Rules: plain English; only use the facts given; say clearly when something \
         could be innocent; never claim an attack is confirmed; suggest observation \
         and verification steps only — never instruct the operator to block, \
         disconnect, or shut anything down (an operator may choose to quarantine a \
         device from its detail view; you may mention that as their option, not as \
         an order).\n\nFACTS\n",
    );
    prompt.push_str(&format!(
        "Counts: {} events, {} alerts, {} canary touches, {} new devices, {} operator actions.\nRanked items:\n",
        report.event_count, report.alert_count, report.canary_touches, report.new_device_count,
        report.operator_action_count,
    ));
    for (index, item) in report.items.iter().enumerate() {
        prompt.push_str(&format!("{}. {} — {}\n", index + 1, item.headline, item.detail));
    }
    prompt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suspicion::Suspicion;

    const NOW: i64 = 1_700_100_000;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn alert(at_s: i64, ip: &str, summary: &str) -> Event {
        let mut event = Event::new(at_s, EventKind::AlertRaised, summary.to_string());
        event.src_ip = Some(ip.parse().unwrap());
        event
    }

    #[test]
    fn a_quiet_day_says_so() {
        let report = daily_report(&[], &HashMap::new(), &HashMap::new(), &HashMap::new(), NOW);
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].headline, "Nothing needs your eyes");
        assert_eq!(report.alert_count, 0);
    }

    #[test]
    fn the_canary_leads_and_the_top_actor_follows() {
        let events = vec![
            alert(NOW - 500, "192.168.1.50", "Canary PLC touched — 192.168.1.50 read holding registers (addr 0, 10 values). Nothing legitimate talks to the canary: this is an intruder."),
            alert(NOW - 400, "10.0.4.10", "[write-from-non-hmi] Office PC wrote to a controller — detail."),
        ];
        let mut scores = HashMap::new();
        scores.insert(ip("192.168.1.50"), Suspicion { score: 100, factors: vec![("Touched the canary PLC".into(), 100)] });
        scores.insert(ip("10.0.4.10"), Suspicion { score: 40, factors: vec![("Wrote to a controller".into(), 40)] });
        let mut names = HashMap::new();
        names.insert(ip("10.0.4.10"), "Office PC (10.0.4.10)".to_string());
        let report = daily_report(&events, &scores, &HashMap::new(), &names, NOW);
        assert!(report.items[0].headline.contains("Canary PLC touched"), "{}", report.items[0].headline);
        assert_eq!(report.canary_touches, 1);
        // The canary visitor is not repeated in the top-actor slot.
        assert!(report.items.iter().filter(|i| i.ip == Some(ip("192.168.1.50"))).count() == 1);
        assert!(report.items[1].headline.contains("Office PC (10.0.4.10) — suspicion 40%"));
        assert!(report.items[1].detail.contains("Wrote to a controller"));
    }

    #[test]
    fn vouches_and_quarantine_are_reported() {
        let mut ignore = Event::new(
            NOW - 300,
            EventKind::OperatorAction,
            "Ignored actor 192.168.50.77 — marked known/expected by banning. GarmWatch keeps watching.".to_string(),
        );
        ignore.src_ip = None;
        let mut quarantined = HashMap::new();
        quarantined.insert(ip("10.0.4.10"), ("banning".to_string(), NOW - 1000));
        let report = daily_report(&[ignore], &HashMap::new(), &quarantined, &HashMap::new(), NOW);
        assert!(report.items[0].headline.contains("in quarantine"), "{}", report.items[0].headline);
        assert!(report.items.iter().any(|i| i.headline.contains("vouched for") && i.detail.contains("by banning")));
        assert_eq!(report.operator_action_count, 1);
    }

    #[test]
    fn the_prompt_carries_the_facts_and_the_rules() {
        let report = daily_report(&[], &HashMap::new(), &HashMap::new(), &HashMap::new(), NOW);
        let prompt = build_triage_prompt(&report);
        assert!(prompt.contains("Nothing needs your eyes"));
        assert!(prompt.contains("never claim an attack is confirmed"));
        assert!(prompt.contains("Check first"));
    }
}
