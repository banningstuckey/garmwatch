//! Layer 3 — the optional local LLM analyst (Phase 6).
//!
//! On demand, GarmWatch hands a local model (Ollama on the same
//! machine) a *digested* incident — the alert, its contributing
//! factors, and a handful of surrounding events, never a raw packet
//! firehose — and gets back a plain-English narrative: what happened,
//! what stage of an attack it resembles, and what to check next.
//!
//! The analyst is advisory prose only. It never feeds detection,
//! never acts, and the app is fully functional when no model is
//! present. This module is transport-agnostic: it builds prompts and
//! Ollama payloads and parses responses (hand-rolled JSON, so the
//! core stays dependency-light); the shell owns the actual HTTP call
//! to 127.0.0.1 and supplies an [`AnalystClient`].

use crate::model::EventKind;
use crate::store::Store;
use std::net::IpAddr;

/// Why an analyst run failed.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalystError {
    /// No alert exists to explain yet.
    NoAlert,
    /// The model endpoint could not be reached or answered badly.
    Transport(String),
    /// The endpoint answered, but not in the expected shape.
    BadResponse(String),
}

impl std::fmt::Display for AnalystError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalystError::NoAlert => write!(f, "no alert to explain yet"),
            AnalystError::Transport(msg) => write!(f, "model endpoint error: {msg}"),
            AnalystError::BadResponse(msg) => write!(f, "unexpected model response: {msg}"),
        }
    }
}

impl std::error::Error for AnalystError {}

/// A client that can turn a prompt into a narrative. The shell
/// implements this over HTTP to Ollama; tests use a mock.
pub trait AnalystClient {
    /// Sends the prompt to the model and returns its narrative.
    fn explain(&self, prompt: &str) -> Result<String, AnalystError>;
}

/// The digested facts about one alert, ready to become a prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct IncidentContext {
    /// The alert event's summary ("[rule] Title — detail").
    pub alert_summary: String,
    /// When the alert fired (Unix seconds).
    pub alert_timestamp: i64,
    /// The device the alert is about, if any.
    pub subject_ip: Option<IpAddr>,
    /// Contributing factors (name, weight) when the alert came from
    /// the anomaly layer and the caller still has them.
    pub factors: Vec<(String, i32)>,
    /// Summaries of events around the alert involving the subject.
    pub surrounding: Vec<String>,
}

impl IncidentContext {
    /// Builds the context for the store's latest alert. Returns
    /// `None` when no alert exists. `extra_factors` lets the caller
    /// attach live anomaly factors for early-warning alerts.
    pub fn for_latest_alert(
        store: &Store,
        extra_factors: Vec<(String, i32)>,
    ) -> Result<Option<IncidentContext>, crate::store::StoreError> {
        let Some(alert) = store.latest_alert()? else {
            return Ok(None);
        };
        let subject = alert.src_ip;
        let mut surrounding = Vec::new();
        for event in store.recent_events(120)? {
            if event.kind == EventKind::AlertRaised {
                continue;
            }
            let involves = match subject {
                Some(ip) => event.src_ip == Some(ip) || event.dst_ip == Some(ip),
                None => true,
            };
            if involves {
                surrounding.push(event.summary.clone());
            }
            if surrounding.len() >= 12 {
                break;
            }
        }
        let factors = if alert.summary.contains("[early-warning]") {
            extra_factors
        } else {
            Vec::new()
        };
        Ok(Some(IncidentContext {
            alert_summary: alert.summary.clone(),
            alert_timestamp: alert.timestamp,
            subject_ip: subject,
            factors,
            surrounding,
        }))
    }
}

/// Builds the analyst prompt from the digested facts. The
/// instructions demand structure, plain English, and honest
/// uncertainty — an analyst that overclaims is worse than none.
pub fn build_prompt(context: &IncidentContext) -> String {
    let mut prompt = String::new();
    prompt.push_str(
        "You are the incident analyst inside GarmWatch, a passive OT (industrial control) \
         network monitor. A detection layer raised the alert below. Write a short incident \
         brief for a plant operator who is not a security specialist.\n\n\
         Use exactly three short sections with these headings:\n\
         What happened\nWhat this resembles\nWhat to check next\n\n\
         Rules: plain English; only use the facts given; say clearly when something is \
         uncertain or could be innocent; never claim an attack is confirmed; suggest \
         observation and verification steps only — never suggest blocking, disconnecting, \
         or shutting anything down.\n\nFACTS\n",
    );
    prompt.push_str(&format!("Alert: {}\n", context.alert_summary));
    if let Some(ip) = context.subject_ip {
        prompt.push_str(&format!("Device in question: {ip}\n"));
    }
    if !context.factors.is_empty() {
        prompt.push_str("Contributing factors (anomaly layer):\n");
        for (name, weight) in &context.factors {
            prompt.push_str(&format!("- {name} (+{weight})\n"));
        }
    }
    if !context.surrounding.is_empty() {
        prompt.push_str("Recent events involving this device (newest first):\n");
        for summary in &context.surrounding {
            prompt.push_str(&format!("- {summary}\n"));
        }
    }
    prompt
}

/// Runs the analyst: prompt → client → narrative.
pub fn explain_incident<C: AnalystClient>(
    client: &C,
    context: &IncidentContext,
) -> Result<String, AnalystError> {
    client.explain(&build_prompt(context))
}

/// Escapes a string for inclusion in a JSON string literal.
pub fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// One progress update from Ollama's model-pull stream.
#[derive(Debug, Clone, PartialEq)]
pub struct PullProgress {
    /// Ollama's status text for the step ("downloading…",
    /// "verifying sha256 digest", "success", …).
    pub status: String,
    /// Download percentage when the line carries byte counts.
    pub percent: Option<u8>,
    /// The error text when the pull failed.
    pub error: Option<String>,
}

/// The Ollama `/api/pull` request body (streaming, so the shell
/// can report progress during a multi-GB download).
pub fn ollama_pull_body(model: &str) -> String {
    format!("{{\"name\":\"{}\",\"stream\":true}}", json_escape(model))
}

/// Extracts a `"key":"value"` string field from a flat JSON line.
fn pull_str_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_string())
}

/// Extracts a `"key":123` number field from a flat JSON line.
fn pull_num_field(line: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let digits: String = line[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Parses one line of Ollama's pull stream. Returns None for
/// lines that carry no status (blank lines, framing noise).
pub fn parse_pull_line(line: &str) -> Option<PullProgress> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if let Some(error) = pull_str_field(line, "error") {
        return Some(PullProgress { status: "error".to_string(), percent: None, error: Some(error) });
    }
    let status = pull_str_field(line, "status")?;
    let percent = match (pull_num_field(line, "total"), pull_num_field(line, "completed")) {
        (Some(total), Some(completed)) if total > 0 => {
            Some(((completed.saturating_mul(100) / total).min(100)) as u8)
        }
        _ => None,
    };
    Some(PullProgress { status, percent, error: None })
}

/// The Ollama `/api/chat` request body (non-streaming).
pub fn ollama_chat_body(model: &str, prompt: &str) -> String {
    format!(
        "{{\"model\":\"{}\",\"stream\":false,\"messages\":[{{\"role\":\"user\",\"content\":\"{}\"}}]}}",
        json_escape(model),
        json_escape(prompt)
    )
}

/// Parses one JSON string literal starting at `bytes[start] == '"'.
/// Returns the decoded string and the index just past the close quote.
fn parse_json_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                let esc = *bytes.get(i + 1)?;
                match esc {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'u' => {
                        let hex = std::str::from_utf8(bytes.get(i + 2..i + 6)?).ok()?;
                        let code = u32::from_str_radix(hex, 16).ok()?;
                        out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        i += 4;
                    }
                    _ => return None,
                }
                i += 2;
            }
            _ => {
                // Copy one UTF-8 codepoint verbatim.
                let s = std::str::from_utf8(&bytes[i..]).ok()?;
                let ch = s.chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    None
}

/// Finds `"key"` in a JSON text and parses the string value after it.
pub fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let bytes = json.as_bytes();
    let needle = format!("\"{key}\"");
    let mut search_from = 0;
    while let Some(pos) = json[search_from..].find(&needle).map(|p| p + search_from) {
        let mut i = pos + needle.len();
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b':') {
            i += 1;
        }
        if bytes.get(i) == Some(&b'"') {
            if let Some((value, _)) = parse_json_string(bytes, i) {
                return Some(value);
            }
        }
        search_from = pos + needle.len();
    }
    None
}

/// Extracts the assistant's narrative from an Ollama chat response.
pub fn parse_ollama_response(json: &str) -> Result<String, AnalystError> {
    extract_json_string(json, "content")
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| AnalystError::BadResponse("no message content found".to_string()))
}

/// Extracts model names from an Ollama `/api/tags` response.
pub fn ollama_model_names(json: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = json;
    while let Some(pos) = rest.find("\"name\"") {
        let after = &rest[pos + 6..];
        if let Some((value, _)) = (|| {
            let bytes = after.as_bytes();
            let mut i = 0;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b':') {
                i += 1;
            }
            parse_json_string(bytes, i)
        })() {
            names.push(value);
        }
        rest = &rest[pos + 6..];
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, EventKind};

    struct MockAnalyst;
    impl AnalystClient for MockAnalyst {
        fn explain(&self, prompt: &str) -> Result<String, AnalystError> {
            Ok(format!("MOCK BRIEF based on: {}", &prompt[..prompt.len().min(60)]))
        }
    }

    fn context() -> IncidentContext {
        IncidentContext {
            alert_summary: "[write-from-non-hmi] Write from a non-HMI device — 10.0.9.77 wrote".to_string(),
            alert_timestamp: 1_700_000_000,
            subject_ip: Some("10.0.9.77".parse().unwrap()),
            factors: vec![("new peer 10.0.1.11".to_string(), 25)],
            surrounding: vec!["Rogue → Line 1 PLC: WRITE".to_string()],
        }
    }

    #[test]
    fn prompt_carries_facts_and_guardrails() {
        let prompt = build_prompt(&context());
        assert!(prompt.contains("[write-from-non-hmi]"));
        assert!(prompt.contains("10.0.9.77"));
        assert!(prompt.contains("new peer 10.0.1.11 (+25)"));
        assert!(prompt.contains("What to check next"));
        assert!(prompt.contains("never suggest blocking"));
    }

    #[test]
    fn ollama_body_is_valid_and_escaped() {
        let body = ollama_chat_body("llama3.1:8b", "say \"hi\"\nnow");
        assert!(body.contains("\"model\":\"llama3.1:8b\""));
        assert!(body.contains("\"stream\":false"));
        assert!(body.contains("say \\\"hi\\\"\\nnow"));
    }

    #[test]
    fn response_content_is_extracted_with_escapes() {
        let json = r#"{"model":"m","message":{"role":"assistant","content":"Line one.\nHe said \"look\" — caf\u00e9."},"done":true}"#;
        let text = parse_ollama_response(json).unwrap();
        assert_eq!(text, "Line one.\nHe said \"look\" — café.");
        assert!(parse_ollama_response("{}").is_err());
    }

    #[test]
    fn model_names_are_extracted() {
        let json = r#"{"models":[{"name":"llama3.1:8b","size":1},{"name":"qwen2.5:7b","size":2}]}"#;
        assert_eq!(ollama_model_names(json), vec!["llama3.1:8b", "qwen2.5:7b"]);
    }

    #[test]
    fn incident_context_and_mock_explain_flow() {
        let store = Store::open_in_memory().unwrap();
        assert!(IncidentContext::for_latest_alert(&store, vec![]).unwrap().is_none());
        let mut alert = Event::new(100, EventKind::AlertRaised, "[new-device] New device — 10.0.9.77");
        alert.src_ip = Some("10.0.9.77".parse().unwrap());
        store.record_event(&alert).unwrap();
        let ctx = IncidentContext::for_latest_alert(&store, vec![]).unwrap().unwrap();
        assert!(ctx.alert_summary.contains("[new-device]"));
        let narrative = explain_incident(&MockAnalyst, &ctx).unwrap();
        assert!(narrative.contains("MOCK BRIEF"));
    }
}

#[cfg(test)]
mod pull_tests {
    use super::*;

    #[test]
    fn pull_body_names_the_model_and_streams() {
        let body = ollama_pull_body("llama3");
        assert!(body.contains("\"name\":\"llama3\""), "{body}");
        assert!(body.contains("\"stream\":true"), "{body}");
    }

    #[test]
    fn pull_progress_reads_byte_counts() {
        let p = parse_pull_line(
            "{\"status\":\"downloading sha256:abc\",\"digest\":\"sha256:abc\",\"total\":1000,\"completed\":430}",
        )
        .expect("progress line");
        assert_eq!(p.percent, Some(43));
        assert!(p.status.contains("downloading"));
        assert!(p.error.is_none());
    }

    #[test]
    fn pull_progress_handles_status_only_success_and_error() {
        let p = parse_pull_line("{\"status\":\"pulling manifest\"}").expect("status line");
        assert_eq!(p.percent, None);
        let done = parse_pull_line("{\"status\":\"success\"}").expect("success line");
        assert_eq!(done.status, "success");
        let err = parse_pull_line("{\"error\":\"model 'nope' not found\"}").expect("error line");
        assert_eq!(err.error.as_deref(), Some("model 'nope' not found"));
        assert!(parse_pull_line("   ").is_none());
        assert!(parse_pull_line("not json").is_none());
    }
}
