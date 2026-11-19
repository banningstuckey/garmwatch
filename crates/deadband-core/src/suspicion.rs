//! Per-actor suspicion scores (feature program, 2026-11-19).
//!
//! Every actor on the network carries a 0–100 suspicion score —
//! Banning's framing: green for a good actor, sliding through
//! yellow and orange to red for a bad one. The score is a ranking
//! heuristic, never a probability and never a black box: it is
//! computed entirely from the stored event log, and every point in
//! it traces to a factor the operator can read ("why are you
//! thinking this is a bad actor" must always have an answer).
//!
//! What feeds it, over a rolling 24-hour window:
//!
//! - **Alerts about the actor**, weighted by the severity of what
//!   fired (a write from a non-HMI outweighs a new-device note),
//!   discounted when they happened during a maintenance window
//!   (expected work), and decaying with age (half-life ~6 hours).
//! - **A canary touch pins the score at 100.** Nothing legitimate
//!   talks to the canary; there is no innocent explanation to
//!   weigh against it, and no operator Ignore can soften it.
//! - **Being newly seen** adds a small amount — new is not bad,
//!   but new is worth a look.
//! - **An operator's Ignore is factored in, never a mute**: it
//!   halves the weight of everything the actor did *before* the
//!   Ignore. Anything after it counts at full weight, so an actor
//!   who misbehaves after being vouched for climbs again — and the
//!   Ignore itself stays in the audit log with who made it.
//! - **Quarantine holds the score at 90+** for as long as the
//!   actor is held: an operator already decided this one is bad
//!   enough to move out of production.

use crate::model::{Event, EventKind};
use std::collections::HashMap;
use std::net::IpAddr;

/// The rolling window the score looks at, in seconds (24 hours).
pub const WINDOW_S: i64 = 24 * 3600;
/// The score a quarantined actor is held at, minimum.
pub const QUARANTINE_FLOOR: i32 = 90;

/// One actor's score and its receipts.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Suspicion {
    /// 0 (no reason to look) to 100 (a canary touch, or worse).
    pub score: i32,
    /// (explanation, points) — points are what the factor added,
    /// or, for an Ignore credit, subtracted (negative). Sorted by
    /// weight, largest first; the display caps the list, the score
    /// never does.
    pub factors: Vec<(String, i32)>,
}

/// Base points for an alert, by the rule tag in its summary —
/// mirroring the severities in `detect.rs` (Critical 40, High 25–30,
/// Medium 15, Low 8). `None` for summaries with no known tag.
fn base_points(summary: &str) -> Option<i32> {
    for (tag, points) in [
        ("[it-to-controller]", 40),
        ("[write-from-non-hmi]", 40),
        ("[threat-intel]", 30),
        ("[rate-spike]", 25),
        ("[write-outside-pattern]", 25),
        ("[early-warning]", 25),
        ("[new-level-crossing]", 15),
        ("[new-device]", 8),
    ] {
        if summary.contains(tag) {
            return Some(points);
        }
    }
    None
}

/// The headline of an alert summary (the part before " — "), for
/// factor lines.
fn headline(summary: &str) -> &str {
    let text = summary.strip_prefix("Maintenance window: ").unwrap_or(summary);
    text.split(" — ").next().unwrap_or(text)
}

/// Age discount: full weight inside the first hour, then halving
/// roughly every 6 hours.
fn decay(age_s: i64) -> f64 {
    if age_s <= 3600 {
        1.0
    } else {
        0.5f64.powf((age_s - 3600) as f64 / (6.0 * 3600.0))
    }
}

/// One parsed Ignore: who made it (from the audit summary).
pub struct IgnoreMark {
    /// When the Ignore was recorded, Unix seconds.
    pub at_s: i64,
    /// The operator who made it.
    pub user: String,
}

/// Parses an "Ignored actor <ip> — … by <user>." audit summary.
pub fn parse_ignore(event: &Event) -> Option<(IpAddr, IgnoreMark)> {
    let rest = event.summary.strip_prefix("Ignored actor ")?;
    let ip: IpAddr = rest.split_whitespace().next()?.parse().ok()?;
    let user = event
        .summary
        .split(" by ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(|word| word.trim_end_matches('.').to_string())
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| "an operator".to_string());
    Some((ip, IgnoreMark { at_s: event.timestamp, user }))
}

/// Computes every actor's suspicion from the event log. `events`
/// should cover at least the last [`WINDOW_S`] seconds (the store
/// helper fetches them); anything older is ignored anyway.
/// `quarantined` maps held actors to (who held them, when).
pub fn compute_all(
    events: &[Event],
    quarantined: &HashMap<IpAddr, (String, i64)>,
    now_s: i64,
) -> HashMap<IpAddr, Suspicion> {
    let window_start = now_s - WINDOW_S;

    // The latest Ignore per actor inside the window.
    let mut ignores: HashMap<IpAddr, IgnoreMark> = HashMap::new();
    for event in events {
        if event.kind != EventKind::OperatorAction || event.timestamp < window_start {
            continue;
        }
        if let Some((ip, mark)) = parse_ignore(event) {
            let entry = ignores.entry(ip).or_insert_with(|| IgnoreMark { at_s: 0, user: String::new() });
            if mark.at_s >= entry.at_s {
                *entry = mark;
            }
        }
    }

    // Alert contributions and discoveries per actor.
    #[derive(Clone)]
    struct Contribution {
        at_s: i64,
        points: i32,
        text: String,
        canary: bool,
    }
    let mut contributions: HashMap<IpAddr, Vec<Contribution>> = HashMap::new();
    let mut discovered: HashMap<IpAddr, i64> = HashMap::new();
    for event in events {
        if event.timestamp < window_start {
            continue;
        }
        match event.kind {
            EventKind::AlertRaised => {
                let Some(ip) = event.src_ip else { continue };
                if event.summary.contains("Canary PLC touched") {
                    contributions.entry(ip).or_default().push(Contribution {
                        at_s: event.timestamp,
                        points: 100,
                        text: "Touched the canary PLC — nothing legitimate talks to it".to_string(),
                        canary: true,
                    });
                    continue;
                }
                let Some(base) = base_points(&event.summary) else { continue };
                let in_window = event.summary.starts_with("Maintenance window: ");
                let mut points = (base as f64 * decay(now_s - event.timestamp)).round() as i32;
                if in_window {
                    points = (points as f64 * 0.25).round() as i32;
                }
                if points <= 0 {
                    continue;
                }
                let mut text = headline(&event.summary).to_string();
                if in_window {
                    text.push_str(" (during a maintenance window)");
                }
                contributions.entry(ip).or_default().push(Contribution {
                    at_s: event.timestamp,
                    points,
                    text,
                    canary: false,
                });
            }
            EventKind::DeviceDiscovered => {
                if let Some(ip) = event.src_ip {
                    discovered.entry(ip).or_insert(event.timestamp);
                }
            }
            _ => {}
        }
    }

    let mut out: HashMap<IpAddr, Suspicion> = HashMap::new();
    let mut actors: Vec<IpAddr> = contributions.keys().chain(discovered.keys()).chain(quarantined.keys()).copied().collect();
    actors.sort();
    actors.dedup();
    for ip in actors {
        let mut factors: Vec<(String, i32)> = Vec::new();
        let mut score: i32 = 0;
        let contribs = contributions.get(&ip).cloned().unwrap_or_default();
        if contribs.iter().any(|c| c.canary) {
            // A canary touch is definitional: pin and stop weighing.
            factors.push(("Touched the canary PLC — nothing legitimate talks to it".to_string(), 100));
            score = 100;
        } else {
            let ignore = ignores.get(&ip);
            let mut saved = 0i32;
            for contribution in &contribs {
                let mut points = contribution.points;
                if let Some(mark) = ignore {
                    if contribution.at_s < mark.at_s {
                        saved += points - points / 2;
                        points /= 2;
                    }
                }
                if points > 0 {
                    score += points;
                    factors.push((contribution.text.clone(), points));
                }
            }
            if let Some(mark) = ignore {
                if saved > 0 {
                    factors.push((
                        format!("Ignored by {} — earlier signals halved (Deadband is still watching)", mark.user),
                        -saved,
                    ));
                }
            }
            if discovered.contains_key(&ip) {
                score += 8;
                factors.push(("First seen on this network within the last day".to_string(), 8));
            }
        }
        if let Some((user, _at)) = quarantined.get(&ip) {
            if score < QUARANTINE_FLOOR {
                score = QUARANTINE_FLOOR;
            }
            factors.insert(
                0,
                (format!("Quarantined by {user} — held out of production"), 0),
            );
        }
        factors.sort_by(|a, b| b.1.abs().cmp(&a.1.abs()));
        factors.truncate(6);
        out.insert(ip, Suspicion { score: score.clamp(0, 100), factors });
    }
    out
}

/// One actor's suspicion (an empty one when nothing is recorded).
pub fn compute(
    events: &[Event],
    quarantined: &HashMap<IpAddr, (String, i64)>,
    ip: IpAddr,
    now_s: i64,
) -> Suspicion {
    compute_all(events, quarantined, now_s).remove(&ip).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_critical_write_scores_and_explains_itself() {
        let events = vec![alert(
            NOW - 600,
            "10.0.4.10",
            "[write-from-non-hmi] Office PC wrote to a controller — A write command reached PLC1 from 10.0.4.10, which is not an HMI.",
        )];
        let suspicion = compute(&events, &HashMap::new(), ip("10.0.4.10"), NOW);
        assert_eq!(suspicion.score, 40);
        assert_eq!(suspicion.factors.len(), 1);
        assert!(suspicion.factors[0].0.contains("wrote to a controller"));
        assert_eq!(suspicion.factors[0].1, 40);
    }

    #[test]
    fn old_alerts_decay_and_window_alerts_discount() {
        // The same critical write, 13 hours old: full 40 in the
        // first hour, then halving every ~6h → about 10.
        let events = vec![alert(NOW - 13 * 3600, "10.0.4.10", "[write-from-non-hmi] Wrote — detail.")];
        let suspicion = compute(&events, &HashMap::new(), ip("10.0.4.10"), NOW);
        assert!(suspicion.score < 40 && suspicion.score > 0, "decayed: {}", suspicion.score);
        // During a maintenance window the same write is expected
        // work: a quarter of the weight.
        let events = vec![alert(
            NOW - 60,
            "10.0.4.10",
            "Maintenance window: [write-from-non-hmi] Wrote — detail.",
        )];
        let suspicion = compute(&events, &HashMap::new(), ip("10.0.4.10"), NOW);
        assert_eq!(suspicion.score, 10);
        assert!(suspicion.factors[0].0.contains("maintenance window"));
    }

    #[test]
    fn an_ignore_halves_what_came_before_it_never_after() {
        let laptop = "192.168.50.77";
        let mut ignore = Event::new(
            NOW - 3000,
            EventKind::OperatorAction,
            format!("Ignored actor {laptop} — marked known/expected by banning. Deadband keeps watching it; later alerts count at full weight."),
        );
        ignore.src_ip = None;
        let events = vec![
            alert(NOW - 3600, laptop, "[write-from-non-hmi] Wrote — before the ignore."),
            alert(NOW - 60, laptop, "[write-from-non-hmi] Wrote — after the ignore."),
            ignore,
        ];
        let suspicion = compute(&events, &HashMap::new(), ip(laptop), NOW);
        // Before: 40 halved to 20. After: full 40. Total 60, with
        // the ignore shown as a −20 credit naming who made it.
        assert_eq!(suspicion.score, 60, "{suspicion:?}");
        assert!(suspicion.factors.iter().any(|(text, points)| *points == -20 && text.contains("banning")));
    }

    #[test]
    fn a_canary_touch_pins_the_score_and_ignores_cannot_soften_it() {
        let visitor = "192.168.1.50";
        let mut ignore = Event::new(
            NOW - 60,
            EventKind::OperatorAction,
            format!("Ignored actor {visitor} — marked known/expected by banning."),
        );
        ignore.src_ip = None;
        let events = vec![
            alert(NOW - 3600, visitor, "Canary PLC touched — 192.168.1.50 read holding registers (addr 0, 10 values). Nothing legitimate talks to the canary: this is an intruder."),
            ignore,
        ];
        let suspicion = compute(&events, &HashMap::new(), ip(visitor), NOW);
        assert_eq!(suspicion.score, 100);
        assert!(suspicion.factors[0].0.contains("canary"));
    }

    #[test]
    fn quarantine_holds_the_floor() {
        let mut quarantined = HashMap::new();
        quarantined.insert(ip("10.0.4.10"), ("banning".to_string(), NOW - 100));
        let suspicion = compute(&[], &quarantined, ip("10.0.4.10"), NOW);
        assert_eq!(suspicion.score, QUARANTINE_FLOOR);
        assert!(suspicion.factors[0].0.contains("Quarantined by banning"));
    }

    #[test]
    fn a_quiet_known_device_scores_zero() {
        let suspicion = compute(&[], &HashMap::new(), ip("10.0.1.11"), NOW);
        assert_eq!(suspicion.score, 0);
        assert!(suspicion.factors.is_empty());
    }
}
