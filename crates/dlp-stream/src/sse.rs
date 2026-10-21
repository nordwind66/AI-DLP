#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub has_data: bool,
    pub id: Option<String>,
    pub retry: Option<String>,
    pub comments: Vec<String>,
}

impl SseEvent {
    pub fn data(data: &str) -> SseEvent {
        SseEvent { data: data.to_string(), has_data: true, ..Default::default() }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut s = String::new();
        for c in &self.comments {
            s.push_str(&format!(":{c}\n"));
        }
        if let Some(e) = &self.event {
            s.push_str(&format!("event: {e}\n"));
        }
        if let Some(i) = &self.id {
            s.push_str(&format!("id: {i}\n"));
        }
        if let Some(r) = &self.retry {
            s.push_str(&format!("retry: {r}\n"));
        }
        if self.has_data {
            for line in self.data.split('\n') {
                s.push_str("data: ");
                s.push_str(line);
                s.push('\n');
            }
        }
        s.push('\n');
        s.into_bytes()
    }
    fn is_empty(&self) -> bool {
        self.event.is_none() && !self.has_data && self.id.is_none() && self.retry.is_none() && self.comments.is_empty()
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum StreamError {
    #[error("sse event exceeds {0} bytes")]
    EventTooLarge(usize),
    #[error("buffered stream exceeds {0} bytes (strict mode cannot continue)")]
    BufferLimit(usize),
    #[error("scanner failure: {0}")]
    Scanner(String),
}

pub struct SseParser {
    buf: Vec<u8>,
    cur: SseEvent,
    skip_lf: bool,
    max_event_bytes: usize,
    cur_bytes: usize,
    /// number of lines that contained invalid UTF-8 (decoded with U+FFFD)
    pub invalid_utf8_lines: usize,
}

impl SseParser {
    pub fn new(max_event_bytes: usize) -> SseParser {
        SseParser { buf: Vec::new(), cur: SseEvent::default(), skip_lf: false, max_event_bytes, cur_bytes: 0, invalid_utf8_lines: 0 }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, StreamError> {
        let mut out = Vec::new();
        for &b in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\n' | b'\r' => {
                    if b == b'\r' {
                        self.skip_lf = true;
                    }
                    let line = std::mem::take(&mut self.buf);
                    if let Some(ev) = self.line(&line)? {
                        out.push(ev);
                    }
                }
                _ => {
                    self.buf.push(b);
                    if self.buf.len() + self.cur_bytes > self.max_event_bytes {
                        return Err(StreamError::EventTooLarge(self.max_event_bytes));
                    }
                }
            }
        }
        Ok(out)
    }

    fn line(&mut self, raw: &[u8]) -> Result<Option<SseEvent>, StreamError> {
        if raw.is_empty() {
            if self.cur.is_empty() {
                return Ok(None);
            }
            self.cur_bytes = 0;
            return Ok(Some(std::mem::take(&mut self.cur)));
        }
        let line = match std::str::from_utf8(raw) {
            Ok(s) => std::borrow::Cow::Borrowed(s),
            Err(_) => {
                self.invalid_utf8_lines += 1;
                String::from_utf8_lossy(raw)
            }
        };
        self.cur_bytes += line.len();
        if self.cur_bytes > self.max_event_bytes {
            return Err(StreamError::EventTooLarge(self.max_event_bytes));
        }
        if let Some(c) = line.strip_prefix(':') {
            self.cur.comments.push(c.to_string());
            return Ok(None);
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (&*line, ""),
        };
        match field {
            "event" => self.cur.event = Some(value.to_string()),
            "data" => {
                if self.cur.has_data {
                    self.cur.data.push('\n');
                }
                self.cur.data.push_str(value);
                self.cur.has_data = true;
            }
            "id" => self.cur.id = Some(value.to_string()),
            "retry" => self.cur.retry = Some(value.to_string()),
            _ => {}
        }
        Ok(None)
    }

    /// End of input. Returns events completed by flushing a trailing unterminated line, plus whether
    /// an incomplete (never dispatched) event was dropped/closed.
    pub fn finish(&mut self) -> (Vec<SseEvent>, bool) {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            let _ = self.line(&line);
        }
        let incomplete = !self.cur.is_empty();
        if incomplete {
            // keep the data: a stream cut mid-event must still be scanned, never silently dropped
            out.push(std::mem::take(&mut self.cur));
        }
        (out, incomplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crlf_split_multibyte_and_multiline() {
        let mut p = SseParser::new(1 << 20);
        let full = "event: msg\r\ndata: 你好\r\ndata: 第二行\r\n\r\n: ping\n\ndata: x\n\n";
        let bytes = full.as_bytes();
        let mut evs = vec![];
        // feed byte by byte: splits CRLF and every multi-byte char
        for b in bytes {
            evs.extend(p.push(&[*b]).unwrap());
        }
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].event.as_deref(), Some("msg"));
        assert_eq!(evs[0].data, "你好\n第二行");
        assert_eq!(evs[1].comments, vec![" ping"]);
        assert_eq!(evs[2].data, "x");
        assert_eq!(p.invalid_utf8_lines, 0);
        assert_eq!(evs[0].encode(), b"event: msg\ndata: \xe4\xbd\xa0\xe5\xa5\xbd\ndata: \xe7\xac\xac\xe4\xba\x8c\xe8\xa1\x8c\n\n".to_vec());
    }
    #[test]
    fn incomplete_event_is_surfaced_and_limits_enforced() {
        let mut p = SseParser::new(64);
        assert!(p.push(b"data: abc").unwrap().is_empty());
        let (evs, incomplete) = p.finish();
        assert!(incomplete && evs.len() == 1 && evs[0].data == "abc");
        let mut p = SseParser::new(16);
        assert!(matches!(p.push(&[b'a'; 40]), Err(StreamError::EventTooLarge(16))));
    }
    #[test]
    fn invalid_utf8_is_counted_not_fatal() {
        let mut p = SseParser::new(1024);
        let evs = p.push(b"data: a\xff\xfeb\n\n").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(p.invalid_utf8_lines, 1);
        assert!(evs[0].data.contains('\u{FFFD}'));
    }
}
