//! Stream format adapters: locate text deltas and rewrite them in place.
use crate::sse::SseEvent;
use dlp_core::Direction;
use serde_json::Value;

#[derive(Debug, Clone)]
pub enum Kind {
    /// a text fragment of a logical channel (content of choice 0, tool args of call 1, ...)
    Text { channel: String, direction: Direction, text: String, modifiable: bool, json_string: bool },
    /// the stream is finishing: everything buffered must be flushed before this event is forwarded
    Terminal,
    Other,
}

pub trait StreamFormat: Send {
    fn name(&self) -> &'static str;
    fn classify(&mut self, ev: &SseEvent) -> Kind;
    fn rewrite(&self, ev: &SseEvent, new_text: &str) -> SseEvent;
    /// Identifier of the content block an event belongs to (Anthropic `index`, Responses `output_index`),
    /// used to drop a whole integrity-protected block (its start/delta/signature/stop events).
    fn block_id(&self, _ev: &SseEvent) -> Option<String> {
        None
    }
    /// SSE event announcing a block (so clients see an error rather than a silent cut)
    fn error_event(&self, message: &str) -> SseEvent {
        SseEvent { event: Some("error".into()), data: serde_json::json!({"error": {"type": "dlp_blocked", "message": message}}).to_string(), has_data: true, ..Default::default() }
    }
}

pub fn detect_format(first: &SseEvent) -> Box<dyn StreamFormat> {
    if let Ok(v) = serde_json::from_str::<Value>(&first.data) {
        if v.get("choices").is_some() || v.get("object").and_then(|o| o.as_str()).map(|o| o.starts_with("chat.completion")).unwrap_or(false) {
            return Box::new(OpenAiChat);
        }
        let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if t.starts_with("response.") {
            return Box::new(OpenAiResponses);
        }
        if matches!(t, "message_start" | "content_block_start" | "content_block_delta" | "content_block_stop" | "message_delta" | "message_stop" | "ping") {
            return Box::new(Anthropic);
        }
    }
    Box::new(Plain)
}

fn set_json_str(ev: &SseEvent, pointer: &str, new_text: &str) -> SseEvent {
    let mut out = ev.clone();
    if let Ok(mut v) = serde_json::from_str::<Value>(&ev.data) {
        if let Some(slot) = v.pointer_mut(pointer) {
            *slot = Value::String(new_text.to_string());
            out.data = v.to_string();
        }
    }
    out
}

pub struct OpenAiChat;
impl StreamFormat for OpenAiChat {
    fn name(&self) -> &'static str {
        "openai.chat.completions"
    }
    fn classify(&mut self, ev: &SseEvent) -> Kind {
        if ev.data.trim() == "[DONE]" {
            return Kind::Terminal;
        }
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else { return Kind::Other };
        let Some(choices) = v.get("choices").and_then(|c| c.as_array()) else { return Kind::Other };
        for (i, ch) in choices.iter().enumerate() {
            if let Some(d) = ch.get("delta") {
                if let Some(t) = d.get("content").and_then(|t| t.as_str()) {
                    if !t.is_empty() {
                        return Kind::Text { channel: format!("content:{i}"), direction: Direction::Response, text: t.to_string(), modifiable: true, json_string: false };
                    }
                }
                if let Some(t) = d.get("reasoning_content").and_then(|t| t.as_str()) {
                    if !t.is_empty() {
                        return Kind::Text { channel: format!("reasoning:{i}"), direction: Direction::Response, text: t.to_string(), modifiable: true, json_string: false };
                    }
                }
                if let Some(calls) = d.get("tool_calls").and_then(|c| c.as_array()) {
                    for tc in calls {
                        let idx = tc.get("index").and_then(|x| x.as_u64()).unwrap_or(0);
                        if let Some(a) = tc.pointer("/function/arguments").and_then(|a| a.as_str()) {
                            if !a.is_empty() {
                                return Kind::Text { channel: format!("args:{i}:{idx}"), direction: Direction::ToolInput, text: a.to_string(), modifiable: true, json_string: true };
                            }
                        }
                    }
                }
            }
            if ch.get("finish_reason").map(|f| !f.is_null()).unwrap_or(false) {
                return Kind::Terminal;
            }
        }
        Kind::Other
    }
    fn rewrite(&self, ev: &SseEvent, new_text: &str) -> SseEvent {
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else { return ev.clone() };
        let ptr = v["choices"].as_array().and_then(|cs| {
            cs.iter().enumerate().find_map(|(i, ch)| {
                let d = ch.get("delta")?;
                if d.get("content").and_then(|t| t.as_str()).map(|t| !t.is_empty()).unwrap_or(false) {
                    return Some(format!("/choices/{i}/delta/content"));
                }
                if d.get("reasoning_content").and_then(|t| t.as_str()).map(|t| !t.is_empty()).unwrap_or(false) {
                    return Some(format!("/choices/{i}/delta/reasoning_content"));
                }
                let calls = d.get("tool_calls")?.as_array()?;
                calls.iter().enumerate().find_map(|(j, tc)| tc.pointer("/function/arguments").and_then(|a| a.as_str()).filter(|a| !a.is_empty()).map(|_| format!("/choices/{i}/delta/tool_calls/{j}/function/arguments")))
            })
        });
        match ptr {
            Some(p) => set_json_str(ev, &p, new_text),
            None => ev.clone(),
        }
    }
}

pub struct OpenAiResponses;
impl StreamFormat for OpenAiResponses {
    fn name(&self) -> &'static str {
        "openai.responses"
    }
    fn block_id(&self, ev: &SseEvent) -> Option<String> {
        serde_json::from_str::<Value>(&ev.data).ok()?.get("output_index")?.as_u64().map(|i| i.to_string())
    }
    fn classify(&mut self, ev: &SseEvent) -> Kind {
        if ev.data.trim() == "[DONE]" {
            return Kind::Terminal;
        }
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else { return Kind::Other };
        let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let oi = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0);
        let ci = v.get("content_index").and_then(|x| x.as_u64()).unwrap_or(0);
        match t {
            "response.output_text.delta" | "response.refusal.delta" => {
                let d = v.get("delta").and_then(|d| d.as_str()).unwrap_or("");
                if d.is_empty() { Kind::Other } else { Kind::Text { channel: format!("text:{oi}:{ci}"), direction: Direction::Response, text: d.to_string(), modifiable: true, json_string: false } }
            }
            "response.function_call_arguments.delta" => {
                let d = v.get("delta").and_then(|d| d.as_str()).unwrap_or("");
                if d.is_empty() { Kind::Other } else { Kind::Text { channel: format!("args:{oi}"), direction: Direction::ToolInput, text: d.to_string(), modifiable: true, json_string: true } }
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                let d = v.get("delta").and_then(|d| d.as_str()).unwrap_or("");
                if d.is_empty() { Kind::Other } else { Kind::Text { channel: format!("reasoning:{oi}"), direction: Direction::Response, text: d.to_string(), modifiable: false, json_string: false } }
            }
            "response.completed" | "response.failed" | "response.incomplete" => Kind::Terminal,
            _ => Kind::Other,
        }
    }
    fn rewrite(&self, ev: &SseEvent, new_text: &str) -> SseEvent {
        set_json_str(ev, "/delta", new_text)
    }
}

pub struct Anthropic;
impl StreamFormat for Anthropic {
    fn name(&self) -> &'static str {
        "anthropic.messages"
    }
    fn block_id(&self, ev: &SseEvent) -> Option<String> {
        let v = serde_json::from_str::<Value>(&ev.data).ok()?;
        if !matches!(v.get("type")?.as_str()?, "content_block_start" | "content_block_delta" | "content_block_stop") {
            return None;
        }
        v.get("index")?.as_u64().map(|i| i.to_string())
    }
    fn classify(&mut self, ev: &SseEvent) -> Kind {
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else { return Kind::Other };
        match v.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "content_block_delta" => {
                let idx = v.get("index").and_then(|x| x.as_u64()).unwrap_or(0);
                let d = &v["delta"];
                match d.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text_delta" => {
                        let t = d.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        if t.is_empty() { Kind::Other } else { Kind::Text { channel: format!("text:{idx}"), direction: Direction::Response, text: t.to_string(), modifiable: true, json_string: false } }
                    }
                    "input_json_delta" => {
                        let t = d.get("partial_json").and_then(|t| t.as_str()).unwrap_or("");
                        if t.is_empty() { Kind::Other } else { Kind::Text { channel: format!("args:{idx}"), direction: Direction::ToolInput, text: t.to_string(), modifiable: true, json_string: true } }
                    }
                    // signed: scanned (detect only), never rewritten
                    "thinking_delta" => {
                        let t = d.get("thinking").and_then(|t| t.as_str()).unwrap_or("");
                        if t.is_empty() { Kind::Other } else { Kind::Text { channel: format!("thinking:{idx}"), direction: Direction::Response, text: t.to_string(), modifiable: false, json_string: false } }
                    }
                    _ => Kind::Other,
                }
            }
            "message_stop" => Kind::Terminal,
            _ => Kind::Other,
        }
    }
    fn rewrite(&self, ev: &SseEvent, new_text: &str) -> SseEvent {
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else { return ev.clone() };
        match v.pointer("/delta/type").and_then(|t| t.as_str()) {
            Some("text_delta") => set_json_str(ev, "/delta/text", new_text),
            Some("input_json_delta") => set_json_str(ev, "/delta/partial_json", new_text),
            _ => ev.clone(),
        }
    }
}

/// Non-JSON streams: every `data:` payload is text.
pub struct Plain;
impl StreamFormat for Plain {
    fn name(&self) -> &'static str {
        "plain"
    }
    fn classify(&mut self, ev: &SseEvent) -> Kind {
        if ev.data.trim() == "[DONE]" {
            return Kind::Terminal;
        }
        if ev.has_data && !ev.data.is_empty() {
            Kind::Text { channel: "text".into(), direction: Direction::Response, text: ev.data.clone(), modifiable: true, json_string: false }
        } else {
            Kind::Other
        }
    }
    fn rewrite(&self, ev: &SseEvent, new_text: &str) -> SseEvent {
        let mut o = ev.clone();
        o.data = new_text.to_string();
        o.has_data = true;
        o
    }
}
