//! Go `regexp` (RE2) -> Rust `regex` dialect translation.
//!
//! Gitleaks rules are written for Go's regexp package. Both engines are linear-time RE2-style,
//! but they differ in ways that silently change results:
//!
//!  * `\w \d \s \b` are **ASCII-only** in Go and **Unicode-aware** in Rust by default.
//!    We rewrite them to explicit ASCII classes / `(?-u:\b)`.
//!  * `\Q...\E` literal quoting is supported by Go, not by Rust: expanded here.
//!  * `\z` is supported by both; `\Z` by neither.
//!  * Go caps repetition counts at 1000 and Rust has a compiled-size limit: we raise the limit
//!    but keep it bounded so a hostile rule cannot exhaust memory.
//!
//! The translator is purely lexical (it tracks escapes and character classes), it never
//! guesses at semantics. Anything it cannot translate faithfully is reported as an error and
//! the importer marks the rule `unsupported` rather than silently dropping it.
use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone, Default)]
pub struct Translation {
    pub pattern: String,
    /// Human readable notes for the import report (what was rewritten).
    pub notes: Vec<String>,
}

pub fn go_to_rust(pattern: &str) -> Result<Translation, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut notes: Vec<String> = Vec::new();
    let mut i = 0;
    let mut in_class = false;
    let mut class_start = 0usize; // index in `out` just after '[' (and optional '^')
    let mut rewrote_shorthand = false;
    let mut rewrote_boundary = false;
    let mut after_class_shorthand = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            let Some(&n) = chars.get(i + 1) else {
                return Err("trailing backslash".into());
            };
            match n {
                'w' | 'd' | 's' | 'W' | 'D' | 'S' => {
                    rewrote_shorthand = true;
                    if in_class {
                        match n {
                            'w' => out.push_str("0-9A-Za-z_"),
                            'd' => out.push_str("0-9"),
                            's' => out.push_str("\\t\\n\\x0C\\r "),
                            // negated shorthand inside a class: nested (union) class, ASCII semantics
                            'W' => out.push_str("[^0-9A-Za-z_]"),
                            'D' => out.push_str("[^0-9]"),
                            _ => out.push_str("[^\\t\\n\\x0C\\r ]"),
                        }
                        after_class_shorthand = true;
                        i += 2;
                        continue;
                    } else {
                        out.push_str(match n {
                            'w' => "[0-9A-Za-z_]",
                            'd' => "[0-9]",
                            's' => "[\\t\\n\\x0C\\r ]",
                            'W' => "[^0-9A-Za-z_]",
                            'D' => "[^0-9]",
                            _ => "[^\\t\\n\\x0C\\r ]",
                        });
                    }
                    i += 2;
                }
                'b' | 'B' if !in_class => {
                    rewrote_boundary = true;
                    out.push_str(if n == 'b' { "(?-u:\\b)" } else { "(?-u:\\B)" });
                    i += 2;
                }
                'Q' => {
                    // \Q ... \E literal block
                    let mut j = i + 2;
                    while j < chars.len() && !(chars[j] == '\\' && chars.get(j + 1) == Some(&'E')) {
                        let lc = chars[j];
                        if "\\.+*?()|[]{}^$#&-~".contains(lc) {
                            out.push('\\');
                        }
                        out.push(lc);
                        j += 1;
                    }
                    if j >= chars.len() {
                        // Go allows an unterminated \Q; the rest is literal
                        i = j;
                    } else {
                        i = j + 2;
                    }
                    notes.push("expanded \\Q..\\E".into());
                }
                'Z' => return Err("\\Z is not supported by Go regexp".into()),
                'C' => return Err("\\C is not supported".into()),
                _ => {
                    out.push('\\');
                    out.push(n);
                    i += 2;
                }
            }
            continue;
        }
        if in_class {
            if after_class_shorthand && c == '-' {
                // Go: '-' after a shorthand is a literal; Rust would try to build a range
                after_class_shorthand = false;
                out.push_str("\\-");
                i += 1;
                continue;
            }
            after_class_shorthand = false;
            if c == '[' && chars.get(i + 1) == Some(&':') {
                // POSIX class like [:alpha:] — copy through to ":]"
                let mut j = i;
                while j + 1 < chars.len() && !(chars[j] == ':' && chars[j + 1] == ']') {
                    out.push(chars[j]);
                    j += 1;
                }
                if j + 1 < chars.len() {
                    out.push_str(":]");
                    i = j + 2;
                } else {
                    return Err("unterminated POSIX class".into());
                }
                continue;
            }
            if c == '[' {
                // Rust treats an unescaped '[' inside a class as a nested class; Go as a literal.
                out.push_str("\\[");
                i += 1;
                continue;
            }
            if c == ']' && out.len() > class_start {
                in_class = false;
            } else if c == ']' {
                // leading ']' is literal in both engines
                out.push_str("\\]");
                i += 1;
                continue;
            }
            // Rust treats `&&`, `--`, `~~` inside a class as set operators; Go as literals.
            if matches!(c, '&' | '-' | '~') && out.ends_with(c) && !out.ends_with(&format!("\\{c}")) {
                out.pop();
                out.push('\\');
                out.push(c);
                out.push('\\');
                out.push(c);
                i += 1;
                continue;
            }
            out.push(c);
            i += 1;
            continue;
        }
        if c == '[' {
            in_class = true;
            out.push('[');
            i += 1;
            if chars.get(i) == Some(&'^') {
                out.push('^');
                i += 1;
            }
            class_start = out.len();
            // a ']' directly after '[' or '[^' is a literal in Go
            if chars.get(i) == Some(&']') {
                out.push_str("\\]");
                i += 1;
            }
            continue;
        }
        if c == '{' {
            // Go treats `{` as a literal unless it forms a valid repetition `{n}`, `{n,}`, `{n,m}`;
            // Rust rejects such patterns, so escape the literal ones.
            let mut j = i + 1;
            let mut digits = 0;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
                digits += 1;
            }
            let mut valid = digits > 0;
            if valid && j < chars.len() && chars[j] == ',' {
                j += 1;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
            }
            valid = valid && j < chars.len() && chars[j] == '}';
            if !valid {
                out.push_str("\\{");
                notes.push("escaped literal '{'".into());
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    if in_class {
        return Err("unterminated character class".into());
    }
    if rewrote_shorthand {
        notes.push("ASCII-fied \\w \\d \\s (Go semantics)".into());
    }
    if rewrote_boundary {
        notes.push("ASCII word boundary (?-u:\\b)".into());
    }
    Ok(Translation { pattern: out, notes })
}

/// Compile with hard size limits (defence against hostile rules).
pub fn compile(pattern: &str) -> Result<(Regex, Translation), String> {
    let t = go_to_rust(pattern)?;
    let re = RegexBuilder::new(&t.pattern)
        .size_limit(64 * 1024 * 1024)
        .dfa_size_limit(64 * 1024 * 1024)
        .nest_limit(200)
        .build()
        .map_err(|e| format!("{e}"))?;
    Ok((re, t))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ascii_word_boundary_matches_go() {
        // In Go, \b is ASCII: "é" is a non-word char, so "éAKIA..." has a boundary before 'A'.
        let (re, _) = compile(r"\bAKIA[A-Z0-9]{16}\b").unwrap();
        assert!(re.is_match("éAKIAABCDEFGHIJKLMNOP"));
        let plain = Regex::new(r"\bAKIA[A-Z0-9]{16}\b").unwrap();
        assert!(!plain.is_match("éAKIAABCDEFGHIJKLMNOP")); // Rust default differs: documents the need
    }
    #[test]
    fn shorthand_in_class() {
        let (re, _) = compile(r"[\w.-]{3,}@x").unwrap();
        assert!(re.is_match("a.b-c@x"));
        assert!(!re.is_match("é@x") || re.find("é@x").is_none());
    }
    #[test]
    fn literal_brace_like_go() {
        let (re, _) = compile(r"^\$(?:[0-9]+|{[0-9]+})$").unwrap();
        assert!(re.is_match("${12}") && re.is_match("$7") && !re.is_match("x"));
        let (re, _) = compile(r"^\${(?:[A-Z_]+)}$").unwrap();
        assert!(re.is_match("${HOME}"));
        let (re, _) = compile(r"a{2,3}").unwrap(); // real quantifier untouched
        assert!(re.is_match("aa") && !re.is_match("a"));
    }
    #[test]
    fn quote_block() {
        let (re, _) = compile(r"\Qa.b\E+").unwrap();
        assert!(re.is_match("a.bbb"));
        assert!(!re.is_match("axb"));
    }
    #[test]
    fn nested_bracket_literal() {
        let (re, _) = compile(r#"[^"'\[\]\s]+"#).unwrap();
        assert!(re.is_match("abc"));
        let (re2, _) = compile(r"[[]x").unwrap();
        assert!(re2.is_match("[x"));
    }
}
