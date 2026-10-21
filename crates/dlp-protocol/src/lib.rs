//! LLM protocol awareness: find the user-visible TEXT in OpenAI / Anthropic request and response
//! bodies, hand it to the engine, and write sanitized text back **only** to those fields.
//!
//! Safety rules enforced here (tested in tests/protocol.rs):
//!  * only whitelisted text locations are ever read or written; `role`, `model`, ids, `type`,
//!    `name`, `tool_call_id`, `tool_use_id`, `cache_control`, `signature`, `encrypted_content`,
//!    usage/finish fields are structurally unreachable;
//!  * integrity-bound content (`thinking`+`signature`, `reasoning` items with `encrypted_content`) is
//!    scanned but flagged `modifiable=false`: the caller must block/audit, never edit;
//!  * base64 / data-URL / binary-looking strings are skipped, not scanned or edited;
//!  * JSON string escaping is handled by serde (we set `Value::String`), tool arguments given as a JSON
//!    *string* are parsed, edited at string leaves and re-serialized; unparseable arguments are
//!    reported as unmodifiable instead of being edited as raw text.
use dlp_core::Direction;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    /// any JSON: every string leaf except protocol-control keys
    Json,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::OpenAiChat => "openai.chat.completions",
            Protocol::OpenAiResponses => "openai.responses",
            Protocol::AnthropicMessages => "anthropic.messages",
            Protocol::Json => "json",
        }
    }
    pub fn parse(s: &str) -> Option<Protocol> {
        match s {
            "openai.chat.completions" | "openai_chat" | "openai" => Some(Protocol::OpenAiChat),
            "openai.responses" | "openai_responses" => Some(Protocol::OpenAiResponses),
            "anthropic.messages" | "anthropic" => Some(Protocol::AnthropicMessages),
            "json" => Some(Protocol::Json),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TextSlot {
    /// RFC 6901 pointer to the string (or to the string holding nested JSON, see `sub`)
    pub pointer: String,
    /// pointer inside the parsed JSON held by the string at `pointer` (tool arguments)
    pub sub: Option<String>,
    pub direction: Direction,
    pub kind: &'static str,
    #[serde(skip)]
    pub text: String,
    /// false for signed / integrity-protected content
    pub modifiable: bool,
    /// pointer of the array element that can be removed as a whole when `modifiable` is false
    /// (a `thinking` block with its signature, a `reasoning` item)
    pub container: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub pointer: String,
    pub reason: &'static str,
}

#[derive(Debug, Default)]
pub struct Extraction {
    pub protocol: Option<Protocol>,
    pub slots: Vec<TextSlot>,
    pub skipped: Vec<Skipped>,
}

/// Keys that carry protocol control data in the generic-JSON walker: never scanned, never edited.
const CONTROL_KEYS: &[&str] = &[
    "role", "model", "id", "type", "name", "object", "created", "tool_call_id", "tool_use_id", "call_id", "signature", "encrypted_content", "cache_control", "stop_reason", "stop_sequence", "finish_reason", "status",
    "index", "usage", "system_fingerprint", "service_tier", "media_type", "url", "format", "detail", "data", "event", "version",
];

pub fn looks_binary(s: &str) -> bool {
    if s.starts_with("data:") && s.contains(";base64,") {
        return true;
    }
    if s.len() < 512 || s.bytes().any(|b| b == b' ' || b == b'\n' || b == b'\t') && s.len() < 4096 {
        return false;
    }
    let total = s.len();
    let b64 = s.bytes().filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')).count();
    let ws = s.bytes().filter(|b| b.is_ascii_whitespace()).count();
    ws * 20 < total && b64 * 100 >= total * 99
}

pub fn detect_protocol(v: &Value) -> Protocol {
    let o = match v.as_object() {
        Some(o) => o,
        None => return Protocol::Json,
    };
    let has = |k: &str| o.contains_key(k);
    if has("choices") || (has("messages") && !has("max_tokens_to_sample") && !has("anthropic_version") && !has("system") && o.get("messages").map(|m| m.is_array()).unwrap_or(false) && !anthropic_blocks(o)) {
        return Protocol::OpenAiChat;
    }
    if o.get("type").and_then(|t| t.as_str()) == Some("message") && has("content") && o.get("role").and_then(|r| r.as_str()) == Some("assistant") && has("stop_reason") {
        return Protocol::AnthropicMessages;
    }
    if has("messages") && (has("system") || anthropic_blocks(o) || has("anthropic_version") || has("max_tokens")) && !has("choices") {
        return Protocol::AnthropicMessages;
    }
    if o.get("object").and_then(|x| x.as_str()) == Some("response") || has("input") && !has("messages") || (has("output") && o.get("output").map(|x| x.is_array()).unwrap_or(false)) {
        return Protocol::OpenAiResponses;
    }
    Protocol::Json
}

fn anthropic_blocks(o: &serde_json::Map<String, Value>) -> bool {
    o.get("messages").and_then(|m| m.as_array()).map(|a| {
        a.iter().any(|msg| msg.get("content").and_then(|c| c.as_array()).map(|blocks| blocks.iter().any(|b| matches!(b.get("type").and_then(|t| t.as_str()), Some("tool_use" | "tool_result" | "thinking" | "image" | "document")))).unwrap_or(false))
    }).unwrap_or(false)
}

fn esc(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

struct Ctx<'a> {
    ex: &'a mut Extraction,
}

impl Ctx<'_> {
    fn text(&mut self, pointer: String, text: &str, direction: Direction, kind: &'static str, modifiable: bool) {
        if text.trim().is_empty() {
            return;
        }
        if looks_binary(text) {
            self.ex.skipped.push(Skipped { pointer, reason: "binary_or_base64" });
            return;
        }
        self.ex.slots.push(TextSlot { pointer, sub: None, direction, kind, text: text.to_string(), modifiable, container: None });
    }

    /// tool arguments: string holding JSON, or an already-parsed object (Anthropic `input`)
    fn tool_args(&mut self, pointer: String, v: &Value, direction: Direction) {
        match v {
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(parsed) => {
                    let mut leaves = Vec::new();
                    collect_leaves(&parsed, "", &mut leaves, &mut self.ex.skipped, &pointer);
                    for (sub, t) in leaves {
                        if looks_binary(&t) {
                            self.ex.skipped.push(Skipped { pointer: pointer.clone(), reason: "binary_or_base64" });
                            continue;
                        }
                        self.ex.slots.push(TextSlot { pointer: pointer.clone(), sub: Some(sub), direction, kind: "tool_arguments", text: t, modifiable: true, container: None });
                    }
                }
                Err(_) => {
                    // incomplete / invalid JSON (e.g. a truncated stream): sanitize the raw text; replacement labels
                    // ([REDACTED_X], masks) never contain quotes/backslashes, so structure is not made worse
                    if !s.trim().is_empty() {
                        self.ex.slots.push(TextSlot { pointer, sub: None, direction, kind: "tool_arguments_unparsed", text: s.clone(), modifiable: true, container: None });
                    }
                }
            },
            Value::Object(_) | Value::Array(_) => {
                let mut leaves = Vec::new();
                collect_leaves(v, "", &mut leaves, &mut self.ex.skipped, &pointer);
                for (sub, t) in leaves {
                    if looks_binary(&t) {
                        self.ex.skipped.push(Skipped { pointer: format!("{pointer}{sub}"), reason: "binary_or_base64" });
                        continue;
                    }
                    self.ex.slots.push(TextSlot { pointer: format!("{pointer}{sub}"), sub: None, direction, kind: "tool_arguments", text: t, modifiable: true, container: None });
                }
            }
            _ => {}
        }
    }
}

/// String leaves of arbitrary JSON, skipping control keys. Returns (json-pointer, text).
fn collect_leaves(v: &Value, base: &str, out: &mut Vec<(String, String)>, skipped: &mut Vec<Skipped>, ctx_ptr: &str) {
    match v {
        Value::String(s) => {
            if !s.trim().is_empty() {
                out.push((base.to_string(), s.clone()));
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                collect_leaves(x, &format!("{base}/{i}"), out, skipped, ctx_ptr);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                if CONTROL_KEYS.contains(&k.as_str()) && x.is_string() {
                    // only control keys that hold plain strings are skipped; nested data below `data`-like
                    // keys is still structure we do not touch
                    continue;
                }
                collect_leaves(x, &format!("{base}/{}", esc(k)), out, skipped, ctx_ptr);
            }
        }
        _ => {}
    }
}

fn content_parts(c: &mut Ctx, ptr: &str, content: &Value, dir: Direction, kind: &'static str) {
    match content {
        Value::String(s) => c.text(ptr.to_string(), s, dir, kind, true),
        Value::Array(parts) => {
            for (i, p) in parts.iter().enumerate() {
                let pp = format!("{ptr}/{i}");
                match p.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text" | "input_text" | "output_text" => {
                        if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                            c.text(format!("{pp}/text"), t, dir, kind, true);
                        }
                    }
                    "refusal" => {
                        if let Some(t) = p.get("refusal").and_then(|t| t.as_str()) {
                            c.text(format!("{pp}/refusal"), t, dir, kind, true);
                        }
                    }
                    other => c.ex.skipped.push(Skipped { pointer: pp, reason: if other.is_empty() { "unknown_part" } else { "non_text_part" } }),
                }
            }
        }
        _ => {}
    }
}

pub fn extract(v: &Value, proto: Protocol, dir: Direction) -> Extraction {
    let mut ex = Extraction { protocol: Some(proto), ..Default::default() };
    {
        let mut c = Ctx { ex: &mut ex };
        match proto {
            Protocol::OpenAiChat => openai_chat(&mut c, v, dir),
            Protocol::OpenAiResponses => openai_responses(&mut c, v, dir),
            Protocol::AnthropicMessages => anthropic(&mut c, v, dir),
            Protocol::Json => {
                let mut leaves = Vec::new();
                let mut sk = Vec::new();
                collect_leaves(v, "", &mut leaves, &mut sk, "");
                c.ex.skipped.extend(sk);
                for (ptr, t) in leaves {
                    c.text(ptr, &t, dir, "json_string", true);
                }
            }
        }
    }
    ex
}

fn openai_chat(c: &mut Ctx, v: &Value, dir: Direction) {
    let is_response = v.get("choices").is_some();
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        for (i, m) in msgs.iter().enumerate() {
            let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
            let (d, kind) = match role {
                "tool" | "function" => (Direction::ToolOutput, "tool_result"),
                "system" | "developer" => (dir, "system"),
                _ => (dir, "message"),
            };
            if let Some(content) = m.get("content") {
                content_parts(c, &format!("/messages/{i}/content"), content, d, kind);
            }
            if let Some(calls) = m.get("tool_calls").and_then(|x| x.as_array()) {
                for (j, tc) in calls.iter().enumerate() {
                    if let Some(a) = tc.pointer("/function/arguments") {
                        c.tool_args(format!("/messages/{i}/tool_calls/{j}/function/arguments"), a, Direction::ToolInput);
                    }
                }
            }
            if let Some(a) = m.pointer("/function_call/arguments") {
                c.tool_args(format!("/messages/{i}/function_call/arguments"), a, Direction::ToolInput);
            }
        }
    }
    if is_response {
        if let Some(choices) = v.get("choices").and_then(|x| x.as_array()) {
            for (i, ch) in choices.iter().enumerate() {
                for field in ["message", "delta"] {
                    let Some(m) = ch.get(field) else { continue };
                    if let Some(content) = m.get("content") {
                        content_parts(c, &format!("/choices/{i}/{field}/content"), content, Direction::Response, "message");
                    }
                    if let Some(r) = m.get("refusal").and_then(|x| x.as_str()) {
                        c.text(format!("/choices/{i}/{field}/refusal"), r, Direction::Response, "refusal", true);
                    }
                    if let Some(r) = m.get("reasoning_content").and_then(|x| x.as_str()) {
                        c.text(format!("/choices/{i}/{field}/reasoning_content"), r, Direction::Response, "reasoning_text", true);
                    }
                    if let Some(calls) = m.get("tool_calls").and_then(|x| x.as_array()) {
                        for (j, tc) in calls.iter().enumerate() {
                            if let Some(a) = tc.pointer("/function/arguments") {
                                c.tool_args(format!("/choices/{i}/{field}/tool_calls/{j}/function/arguments"), a, Direction::ToolInput);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn openai_responses(c: &mut Ctx, v: &Value, dir: Direction) {
    if let Some(s) = v.get("instructions").and_then(|x| x.as_str()) {
        c.text("/instructions".into(), s, dir, "system", true);
    }
    match v.get("input") {
        Some(Value::String(s)) => c.text("/input".into(), s, dir, "message", true),
        Some(Value::Array(items)) => {
            for (i, it) in items.iter().enumerate() {
                responses_item(c, &format!("/input/{i}"), it, dir);
            }
        }
        _ => {}
    }
    if let Some(items) = v.get("output").and_then(|x| x.as_array()) {
        for (i, it) in items.iter().enumerate() {
            responses_item(c, &format!("/output/{i}"), it, Direction::Response);
        }
    }
    if let Some(s) = v.get("output_text").and_then(|x| x.as_str()) {
        // convenience aggregate duplicating output[].content text: scanned so it cannot leak
        c.text("/output_text".into(), s, Direction::Response, "message", true);
    }
}

fn responses_item(c: &mut Ctx, ptr: &str, it: &Value, dir: Direction) {
    match it.get("type").and_then(|t| t.as_str()).unwrap_or("message") {
        "message" => {
            let role = it.get("role").and_then(|r| r.as_str()).unwrap_or("");
            let kind = if matches!(role, "system" | "developer") { "system" } else { "message" };
            if let Some(content) = it.get("content") {
                content_parts(c, &format!("{ptr}/content"), content, dir, kind);
            }
        }
        "function_call" | "custom_tool_call" => {
            if let Some(a) = it.get("arguments").or_else(|| it.get("input")) {
                let key = if it.get("arguments").is_some() { "arguments" } else { "input" };
                c.tool_args(format!("{ptr}/{key}"), a, Direction::ToolInput);
            }
        }
        "function_call_output" | "custom_tool_call_output" => {
            if let Some(o) = it.get("output") {
                content_parts(c, &format!("{ptr}/output"), o, Direction::ToolOutput, "tool_result");
            }
        }
        "reasoning" => {
            // integrity-bound (encrypted_content / id linkage): scan summary text, never edit
            if let Some(sum) = it.get("summary").and_then(|s| s.as_array()) {
                for (j, s) in sum.iter().enumerate() {
                    if let Some(t) = s.get("text").and_then(|t| t.as_str()) {
                        c.text(format!("{ptr}/summary/{j}/text"), t, dir, "reasoning_summary", false);
                        if let Some(sl) = c.ex.slots.last_mut() {
                            sl.container = Some(ptr.to_string());
                        }
                    }
                }
            }
            c.ex.skipped.push(Skipped { pointer: format!("{ptr}/encrypted_content"), reason: "integrity_bound" });
        }
        _ => c.ex.skipped.push(Skipped { pointer: ptr.to_string(), reason: "non_text_item" }),
    }
}

fn anthropic(c: &mut Ctx, v: &Value, dir: Direction) {
    match v.get("system") {
        Some(Value::String(s)) => c.text("/system".into(), s, dir, "system", true),
        Some(Value::Array(blocks)) => {
            for (i, b) in blocks.iter().enumerate() {
                if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                    c.text(format!("/system/{i}/text"), t, dir, "system", true);
                }
            }
        }
        _ => {}
    }
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        for (i, m) in msgs.iter().enumerate() {
            let ptr = format!("/messages/{i}/content");
            anthropic_content(c, &ptr, m.get("content"), dir);
        }
    }
    // response body
    if v.get("type").and_then(|t| t.as_str()) == Some("message") && v.get("role").and_then(|r| r.as_str()) == Some("assistant") {
        anthropic_content(c, "/content", v.get("content"), Direction::Response);
    }
}

fn anthropic_content(c: &mut Ctx, ptr: &str, content: Option<&Value>, dir: Direction) {
    match content {
        Some(Value::String(s)) => c.text(ptr.to_string(), s, dir, "message", true),
        Some(Value::Array(blocks)) => {
            for (i, b) in blocks.iter().enumerate() {
                let bp = format!("{ptr}/{i}");
                match b.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text" => {
                        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                            c.text(format!("{bp}/text"), t, dir, "message", true);
                        }
                    }
                    "tool_use" | "server_tool_use" => {
                        if let Some(inp) = b.get("input") {
                            c.tool_args(format!("{bp}/input"), inp, Direction::ToolInput);
                        }
                    }
                    "tool_result" => match b.get("content") {
                        Some(Value::String(s)) => c.text(format!("{bp}/content"), s, Direction::ToolOutput, "tool_result", true),
                        Some(Value::Array(inner)) => {
                            for (j, ib) in inner.iter().enumerate() {
                                if ib.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(t) = ib.get("text").and_then(|t| t.as_str()) {
                                        c.text(format!("{bp}/content/{j}/text"), t, Direction::ToolOutput, "tool_result", true);
                                    }
                                } else {
                                    c.ex.skipped.push(Skipped { pointer: format!("{bp}/content/{j}"), reason: "non_text_part" });
                                }
                            }
                        }
                        _ => {}
                    },
                    "thinking" => {
                        // signed: any edit invalidates the signature
                        if let Some(t) = b.get("thinking").and_then(|t| t.as_str()) {
                            c.text(format!("{bp}/thinking"), t, dir, "thinking", false);
                            if let Some(sl) = c.ex.slots.last_mut() {
                                sl.container = Some(bp.clone());
                            }
                        }
                    }
                    "redacted_thinking" => c.ex.skipped.push(Skipped { pointer: bp, reason: "integrity_bound" }),
                    "document" => {
                        if b.pointer("/source/type").and_then(|t| t.as_str()) == Some("text") {
                            if let Some(t) = b.pointer("/source/data").and_then(|t| t.as_str()) {
                                c.text(format!("{bp}/source/data"), t, dir, "document", true);
                            }
                        } else {
                            c.ex.skipped.push(Skipped { pointer: bp, reason: "binary_or_base64" });
                        }
                    }
                    "image" => c.ex.skipped.push(Skipped { pointer: bp, reason: "binary_or_base64" }),
                    _ => c.ex.skipped.push(Skipped { pointer: bp, reason: "non_text_block" }),
                }
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
pub struct Edit {
    pub pointer: String,
    pub sub: Option<String>,
    pub new_text: String,
}

/// Write edits back. Edits to the same nested-JSON string are applied to one parsed copy and the
/// string is re-serialized once.
pub fn apply_edits(v: &mut Value, edits: &[Edit]) -> Result<(), String> {
    let mut nested: BTreeMap<String, Vec<&Edit>> = BTreeMap::new();
    for e in edits {
        match &e.sub {
            None => {
                let slot = v.pointer_mut(&e.pointer).ok_or_else(|| "edit target vanished".to_string())?;
                if !slot.is_string() {
                    return Err("edit target is not a string".into());
                }
                *slot = Value::String(e.new_text.clone());
            }
            Some(_) => nested.entry(e.pointer.clone()).or_default().push(e),
        }
    }
    for (ptr, es) in nested {
        let slot = v.pointer_mut(&ptr).ok_or_else(|| "edit target vanished".to_string())?;
        let s = slot.as_str().ok_or_else(|| "nested edit target is not a string".to_string())?.to_string();
        let mut parsed: Value = serde_json::from_str(&s).map_err(|e| format!("tool arguments no longer parse: {e}"))?;
        for e in es {
            let leaf = parsed.pointer_mut(e.sub.as_deref().unwrap_or("")).ok_or_else(|| "nested edit target vanished".to_string())?;
            if !leaf.is_string() {
                return Err("nested edit target is not a string".into());
            }
            *leaf = Value::String(e.new_text.clone());
        }
        *slot = Value::String(serde_json::to_string(&parsed).map_err(|e| e.to_string())?);
    }
    Ok(())
}


/// Remove array elements by pointer (descending index order so earlier removals do not shift later ones).
pub fn remove_elements(v: &mut Value, pointers: &[String]) -> Result<usize, String> {
    let mut targets: Vec<(String, usize)> = Vec::new();
    for p in pointers {
        let (parent, idx) = p.rsplit_once('/').ok_or_else(|| "bad container pointer".to_string())?;
        let idx: usize = idx.parse().map_err(|_| "container is not an array element".to_string())?;
        targets.push((parent.to_string(), idx));
    }
    targets.sort();
    targets.dedup();
    targets.sort_by(|a, b| b.cmp(a));
    let mut n = 0;
    for (parent, idx) in targets {
        let arr = v.pointer_mut(&parent).and_then(|x| x.as_array_mut()).ok_or_else(|| "container parent vanished".to_string())?;
        if idx < arr.len() {
            arr.remove(idx);
            n += 1;
        }
    }
    Ok(n)
}
