//! Stream scanner: strict (full buffering) and window (provable hold-back) modes.
//!
//! Strict mode never releases a byte of content before the whole response has been inspected:
//! text deltas AND the events around them are held, then flushed in order with sanitized text.
//!
//! Window mode releases text early, but only when the engine can prove a bound `M` on the length of
//! any entity the active detectors can produce (regex `maximum_len` + context windows). Text older
//! than `M` bytes behind the newest byte, and not overlapping a detected entity, cannot be part of an
//! undetected entity; everything newer is held back. NLP detectors have no such bound, therefore a
//! policy that uses them (or any unbounded rule such as a PEM block) falls back to strict mode –
//! never to "just pass it through".
use crate::format::*;
use crate::sse::*;
use dlp_core::{ceil_char_boundary, floor_char_boundary, Direction};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub struct Span {
    pub entity_type: String,
    /// byte offsets in the text that was scanned
    pub start: usize,
    pub end: usize,
    pub replacement: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOut {
    pub spans: Vec<Span>,
    pub blocked: Option<String>,
    pub degraded: bool,
    pub counts: BTreeMap<String, usize>,
    /// detections that the policy wants acted on (needed for unmodifiable channels)
    pub actionable: usize,
}

pub trait TextScanner: Send {
    fn scan(&mut self, text: &str, direction: Direction) -> Result<ScanOut, String>;
    /// Largest number of bytes any entity can span with the active detectors; `None` = unbounded/unknown.
    fn window_bound(&self) -> Option<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedMode {
    Strict,
    Window,
}

/// What to do with sensitive data inside an unmodifiable (signed / integrity-protected) channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmodAction {
    /// remove the whole content block from the forwarded stream (default: desensitize, don't refuse)
    Drop,
    /// terminate the stream with an error event
    Block,
    /// forward unchanged, record a warning
    Audit,
}

#[derive(Debug, Clone)]
pub struct StreamConfig {
    pub requested: RequestedMode,
    pub max_buffer_bytes: usize,
    pub max_event_bytes: usize,
    /// handling of sensitive data in unmodifiable channels
    pub unmodifiable: UnmodAction,
}
impl Default for StreamConfig {
    fn default() -> Self {
        StreamConfig { requested: RequestedMode::Strict, max_buffer_bytes: 4 << 20, max_event_bytes: 1 << 20, unmodifiable: UnmodAction::Drop }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StreamStats {
    pub format: String,
    pub effective_mode: String,
    pub fallback_reason: Option<String>,
    pub blocked: Option<String>,
    pub events_in: usize,
    pub events_out: usize,
    pub max_held_bytes: usize,
    pub entity_counts: BTreeMap<String, usize>,
    pub degraded: bool,
    pub invalid_utf8_lines: usize,
    pub incomplete_tail: bool,
    pub warnings: Vec<String>,
}

enum Held {
    Pass(SseEvent),
    Text { ev: SseEvent, channel: String, len: usize },
}

struct Chan {
    text: String,
    direction: Direction,
    modifiable: bool,
    json_string: bool,
    // window state (content channels only)
    windowed: bool,
    tail_ctx: String,
    template: Option<SseEvent>,
    block: Option<String>,
}

pub struct StreamScanner<S: TextScanner> {
    cfg: StreamConfig,
    scanner: S,
    parser: SseParser,
    format: Option<Box<dyn StreamFormat>>,
    held: Vec<Held>,
    chans: HashMap<String, Chan>,
    chan_order: Vec<String>,
    held_bytes: usize,
    bound: Option<usize>,
    window: bool,
    text_seen: bool,
    flushed_once: bool,
    dropped_blocks: std::collections::HashSet<String>,
    ended: bool,
    pub stats: StreamStats,
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn render(text: &str, spans: &[Span], from: usize, to: usize, json_string: bool) -> String {
    let mut out = String::with_capacity(to - from);
    let mut pos = from;
    for sp in spans.iter().filter(|s| s.end > from && s.start < to) {
        if sp.start < from {
            // the entity began in an earlier delta (its replacement was emitted there): skip the
            // part of it that falls into this delta so no fragment of the original value survives
            pos = pos.max(sp.end.min(to));
            continue;
        }
        if sp.start < pos {
            continue;
        }
        out.push_str(&text[pos..sp.start]);
        if json_string {
            out.push_str(&json_escape(&sp.replacement));
        } else {
            out.push_str(&sp.replacement);
        }
        pos = sp.end.min(to).max(pos);
    }
    if pos < to {
        out.push_str(&text[pos..to]);
    }
    out
}

impl<S: TextScanner> StreamScanner<S> {
    pub fn new(cfg: StreamConfig, scanner: S) -> Self {
        let bound = scanner.window_bound();
        let mut stats = StreamStats::default();
        let window = match (cfg.requested, bound) {
            (RequestedMode::Window, Some(b)) if b > 0 => true,
            (RequestedMode::Window, _) => {
                stats.fallback_reason = Some("window mode requires a provable entity length bound (rule-only detectors, no unbounded patterns); using strict buffering".into());
                false
            }
            _ => false,
        };
        stats.effective_mode = if window { "window" } else { "strict" }.into();
        StreamScanner { parser: SseParser::new(cfg.max_event_bytes), cfg, scanner, format: None, held: vec![], chans: HashMap::new(), chan_order: vec![], held_bytes: 0, bound, window, text_seen: false, flushed_once: false, dropped_blocks: Default::default(), ended: false, stats }
    }

    pub fn is_blocked(&self) -> bool {
        self.stats.blocked.is_some()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.ended {
            return out;
        }
        match self.parser.push(bytes) {
            Ok(evs) => {
                for ev in evs {
                    self.handle(ev, &mut out);
                    if self.ended {
                        break;
                    }
                }
            }
            Err(e) => self.block(format!("stream error: {e}"), &mut out),
        }
        self.stats.invalid_utf8_lines = self.parser.invalid_utf8_lines;
        out
    }

    /// End of upstream. Flushes everything (verdict first), including an unterminated last event.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.ended {
            return out;
        }
        let (evs, incomplete) = self.parser.finish();
        self.stats.incomplete_tail = incomplete;
        if incomplete {
            self.stats.warnings.push("stream ended inside an SSE event; the partial event was scanned".into());
        }
        for ev in evs {
            self.handle(ev, &mut out);
            if self.ended {
                return out;
            }
        }
        self.flush_all(&mut out);
        self.stats.invalid_utf8_lines = self.parser.invalid_utf8_lines;
        out
    }

    fn emit(&mut self, ev: &SseEvent, out: &mut Vec<u8>) {
        out.extend(ev.encode());
        self.stats.events_out += 1;
    }

    fn block(&mut self, reason: String, out: &mut Vec<u8>) {
        if self.stats.blocked.is_some() {
            return;
        }
        let ev = match &self.format {
            Some(f) => f.error_event(&reason),
            None => Plain.error_event(&reason),
        };
        // nothing held is ever released; the client only sees the error event
        self.held.clear();
        self.chans.clear();
        self.held_bytes = 0;
        self.stats.blocked = Some(reason);
        self.emit(&ev, out);
        self.ended = true;
    }

    fn handle(&mut self, ev: SseEvent, out: &mut Vec<u8>) {
        self.stats.events_in += 1;
        if self.format.is_none() && ev.has_data {
            let f = detect_format(&ev);
            self.stats.format = f.name().into();
            self.format = Some(f);
        }
        let kind = match self.format.as_mut() {
            Some(f) => f.classify(&ev),
            None => Kind::Other,
        };
        match kind {
            Kind::Text { channel, direction, text, modifiable, json_string } => {
                self.text_seen = true;
                let windowed = self.window && modifiable && !json_string && channel.starts_with("content") || self.window && modifiable && !json_string && channel.starts_with("text");
                let c = self.chans.entry(channel.clone()).or_insert_with(|| Chan { text: String::new(), direction, modifiable, json_string, windowed, tail_ctx: String::new(), template: None, block: self.format.as_ref().and_then(|f| f.block_id(&ev)) });
                if !self.chan_order.contains(&channel) {
                    self.chan_order.push(channel.clone());
                }
                if c.windowed {
                    c.text.push_str(&text);
                    c.template = Some(ev.clone());
                    self.held_bytes += text.len();
                    self.stats.max_held_bytes = self.stats.max_held_bytes.max(self.held_bytes);
                    self.release_window(&channel, false, out);
                } else {
                    c.text.push_str(&text);
                    self.held_bytes += text.len();
                    self.held.push(Held::Text { ev, channel, len: text.len() });
                    self.stats.max_held_bytes = self.stats.max_held_bytes.max(self.held_bytes);
                }
                if self.held_bytes > self.cfg.max_buffer_bytes {
                    self.block(format!("{}", StreamError::BufferLimit(self.cfg.max_buffer_bytes)), out);
                }
            }
            Kind::Terminal => {
                self.flush_all(out);
                if !self.ended {
                    self.emit(&ev, out);
                }
            }
            Kind::Other => {
                if self.window {
                    // window mode forwards control events immediately
                    self.emit(&ev, out);
                } else if !self.flushed_once || !self.held.is_empty() {
                    // strict: nothing leaves before the verdict (this also lets a dropped block's
                    // start/signature/stop events be removed together with its text)
                    self.held.push(Held::Pass(ev));
                } else {
                    self.emit(&ev, out);
                }
            }
        }
    }

    fn scan_checked(&mut self, text: &str, direction: Direction, modifiable: bool, out: &mut Vec<u8>) -> Option<ScanOut> {
        match self.scanner.scan(text, direction) {
            Err(e) => {
                self.block(format!("detection failed (fail-closed): {e}"), out);
                None
            }
            Ok(r) => {
                self.stats.degraded |= r.degraded;
                if let Some(b) = r.blocked.clone() {
                    self.block(format!("policy block: {b}"), out);
                    return None;
                }
                if !modifiable && r.actionable > 0 {
                    let msg = "sensitive data in an unmodifiable (signed) stream channel".to_string();
                    match self.cfg.unmodifiable {
                        UnmodAction::Block => {
                            self.block(msg, out);
                            return None;
                        }
                        UnmodAction::Drop => self.stats.warnings.push(format!("{msg}; the whole block is removed from the forwarded stream")),
                        UnmodAction::Audit => self.stats.warnings.push(format!("{msg}; forwarded unchanged (policy unmodifiable_action=audit)")),
                    }
                }
                Some(r)
            }
        }
    }

    fn count(&mut self, r: &ScanOut) {
        for (k, v) in &r.counts {
            *self.stats.entity_counts.entry(k.clone()).or_insert(0) += v;
        }
    }

    /// Window mode: release the safe prefix of a content channel.
    fn release_window(&mut self, channel: &str, final_flush: bool, out: &mut Vec<u8>) {
        let m = self.bound.unwrap_or(0);
        let (ctx, pending, dir, template) = {
            let c = self.chans.get_mut(channel).unwrap();
            if c.text.is_empty() {
                return;
            }
            (std::mem::take(&mut c.tail_ctx), std::mem::take(&mut c.text), c.direction, c.template.clone())
        };
        let scan_text = format!("{ctx}{pending}");
        let Some(res) = self.scan_checked(&scan_text, dir, true, out) else { return };
        let ctx_len = ctx.len();
        // an entity straddling the already-released boundary would break the hold-back argument
        if res.spans.iter().any(|s| s.start < ctx_len && s.end > ctx_len) {
            self.block("window invariant violated (entity crosses the release boundary)".into(), out);
            return;
        }
        let mut b = if final_flush { scan_text.len() } else { ctx_len + floor_char_boundary(&pending, pending.len().saturating_sub(m)) };
        loop {
            let mut moved = false;
            for s in &res.spans {
                if s.start < b && s.end > b && s.start >= ctx_len {
                    b = s.end;
                    moved = true;
                }
            }
            if !moved {
                break;
            }
        }
        b = ceil_char_boundary(&scan_text, b.min(scan_text.len()));
        for sp in res.spans.iter().filter(|s| s.start >= ctx_len && s.end <= b) {
            *self.stats.entity_counts.entry(sp.entity_type.clone()).or_insert(0) += 1;
        }
        let rendered = render(&scan_text, &res.spans, ctx_len, b, false);
        let released_orig = &scan_text[ctx_len..b];
        // lookbehind for the next scan: last M bytes of everything released so far
        let keep_from = ceil_char_boundary(&scan_text, b.saturating_sub(m));
        let new_ctx = scan_text[keep_from..b].to_string();
        let rest = scan_text[b..].to_string();
        self.held_bytes = self.held_bytes.saturating_sub(released_orig.len());
        {
            let c = self.chans.get_mut(channel).unwrap();
            c.tail_ctx = new_ctx;
            c.text = rest;
        }
        if !rendered.is_empty() {
            if let (Some(t), Some(f)) = (template, self.format.as_ref()) {
                let ev = f.rewrite(&t, &rendered);
                self.emit(&ev, out);
            }
        }
    }

    fn flush_all(&mut self, out: &mut Vec<u8>) {
        if self.ended {
            return;
        }
        // window channels: final release of everything pending
        let window_chans: Vec<String> = self.chan_order.iter().filter(|c| self.chans.get(*c).map(|x| x.windowed).unwrap_or(false)).cloned().collect();
        for ch in window_chans {
            self.release_window(&ch, true, out);
            if self.ended {
                return;
            }
        }
        // strict channels
        let order: Vec<String> = self.chan_order.iter().filter(|c| self.chans.get(*c).map(|x| !x.windowed).unwrap_or(false)).cloned().collect();
        let mut results: HashMap<String, (ScanOut, String)> = HashMap::new();
        for ch in &order {
            let (text, dir, modifiable) = {
                let c = &self.chans[ch];
                (c.text.clone(), c.direction, c.modifiable)
            };
            if text.is_empty() {
                continue;
            }
            let Some(r) = self.scan_checked(&text, dir, modifiable, out) else { return };
            self.count(&r);
            if !self.chans[ch].modifiable && r.actionable > 0 && self.cfg.unmodifiable == UnmodAction::Drop {
                if let Some(b) = self.chans[ch].block.clone() {
                    self.dropped_blocks.insert(b);
                }
            }
            results.insert(ch.clone(), (r, text));
        }
        // emit held events in order with per-delta rendering
        let held = std::mem::take(&mut self.held);
        let mut offsets: HashMap<String, usize> = HashMap::new();
        for h in held {
            if !self.dropped_blocks.is_empty() {
                let evref = match &h {
                    Held::Pass(ev) => ev,
                    Held::Text { ev, .. } => ev,
                };
                if let Some(b) = self.format.as_ref().and_then(|f| f.block_id(evref)) {
                    if self.dropped_blocks.contains(&b) {
                        continue;
                    }
                }
            }
            match h {
                Held::Pass(ev) => self.emit(&ev, out),
                Held::Text { ev, channel, len } => {
                    let off = *offsets.get(&channel).unwrap_or(&0);
                    offsets.insert(channel.clone(), off + len);
                    let (modifiable, json_string) = {
                        let c = &self.chans[&channel];
                        (c.modifiable, c.json_string)
                    };
                    match (results.get(&channel), modifiable) {
                        (Some((r, text)), true) if !r.spans.is_empty() => {
                            let piece = render(text, &r.spans, off, off + len, json_string);
                            if piece == text[off..off + len] {
                                self.emit(&ev, out);
                            } else {
                                let f = self.format.as_ref().expect("format known when text seen");
                                let nev = f.rewrite(&ev, &piece);
                                self.emit(&nev, out);
                            }
                        }
                        _ => self.emit(&ev, out),
                    }
                }
            }
        }
        for ch in order {
            if let Some(c) = self.chans.get_mut(&ch) {
                c.text.clear();
            }
        }
        self.held_bytes = 0;
        self.flushed_once = true;
        self.dropped_blocks.clear();
        self.chans.retain(|_, c| c.windowed);
        self.chan_order.retain(|c| self.chans.contains_key(c));
    }
}
