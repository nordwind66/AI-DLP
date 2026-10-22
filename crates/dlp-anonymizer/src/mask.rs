//! Partial masking and fixed redaction labels.
//! Examples: `138****8000`, `z***@example.com`, `110***********0027`, `************1111`, `张*`.

/// Fixed label for REDACT: `[REDACTED_API_KEY]`.
pub fn redact_label(entity_type: &str) -> String {
    let clean: String = entity_type.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
    format!("[REDACTED_{clean}]")
}

fn keep_edges(chars: &[char], head: usize, tail: usize) -> String {
    let n = chars.len();
    // never reveal more than half of the value, whatever the policy asks for
    let budget = n / 2;
    let (mut h, mut t) = (head, tail);
    while h + t > budget {
        if t > 0 {
            t -= 1;
        } else if h > 0 {
            h -= 1;
        }
    }
    let mut s = String::with_capacity(n);
    for (i, c) in chars.iter().enumerate() {
        if i < h || i >= n - t {
            s.push(*c);
        } else {
            s.push('*');
        }
    }
    s
}

fn keep_edges_min_hidden(chars: &[char], head: usize, tail: usize, min_hidden: usize) -> String {
    let n = chars.len();
    let budget = n.saturating_sub(min_hidden);
    let (mut h, mut t) = (head, tail);
    while h + t > budget {
        if t > 0 { t -= 1 } else if h > 0 { h -= 1 }
    }
    chars.iter().enumerate().map(|(i, c)| if i < h || i >= n - t { *c } else { '*' }).collect()
}

/// Mask only digits, keep separators (for phone numbers / cards written with spaces or dashes).
fn mask_digits_keep_edges(value: &str, head: usize, tail: usize, min_hidden: usize) -> String {
    let total = value.chars().filter(|c| c.is_ascii_digit()).count();
    // structured numbers: always hide at least `min_hidden` digits
    let budget = total.saturating_sub(min_hidden);
    let (mut h, mut t) = (head, tail);
    while h + t > budget {
        if t > 0 {
            t -= 1;
        } else if h > 0 {
            h -= 1;
        }
    }
    let mut seen = 0;
    value
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                seen += 1;
                if seen <= h || seen > total - t {
                    c
                } else {
                    '*'
                }
            } else {
                c
            }
        })
        .collect()
}

/// Full-width digits / plus / hyphen / space (１３８－…) folded to ASCII so structured masks work on them.
fn fold_wide(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '０'..='９' => char::from(b'0' + (c as u32 - '０' as u32) as u8),
            '＋' => '+',
            '－' => '-',
            '\u{3000}' => ' ',
            c => c,
        })
        .collect()
}

pub fn mask_value(entity_type: &str, value: &str) -> String {
    let folded;
    let value = if matches!(entity_type, "PHONE_NUMBER" | "BANK_CARD" | "CREDIT_CARD" | "BANK_ACCOUNT") && !value.is_ascii() {
        folded = fold_wide(value);
        folded.as_str()
    } else {
        value
    };
    let chars: Vec<char> = value.chars().collect();
    match entity_type {
        "PHONE_NUMBER" => {
            // keep a recognised country-code prefix ("+86 ", "+1-") out of the head/tail budget
            for cc in ["+86", "+1"] {
                if let Some(rest) = value.strip_prefix(cc) {
                    let sep_len = rest.chars().take_while(|c| matches!(c, ' ' | '-')).count();
                    let (sep, body) = rest.split_at(sep_len);
                    return format!("{cc}{sep}{}", mask_digits_keep_edges(body, 3, 4, 4));
                }
            }
            mask_digits_keep_edges(value, 3, 4, 4)
        }
        "EMAIL_ADDRESS" => match value.rsplit_once(['@', '＠']) {
            Some((local, domain)) => {
                let first: String = local.chars().take(1).collect();
                format!("{first}***@{domain}")
            }
            None => keep_edges(&chars, 1, 0),
        },
        "CN_ID_CARD" => {
            let c: Vec<char> = value.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
            keep_edges_min_hidden(&c, 3, 4, 8)
        }
        "BANK_CARD" | "CREDIT_CARD" | "BANK_ACCOUNT" => mask_digits_keep_edges(value, 0, 4, 8),
        "PERSON" => {
            if chars.len() <= 1 {
                "*".into()
            } else if chars.iter().any(|c| ('\u{4e00}'..='\u{9fff}').contains(c)) {
                let mut s = String::new();
                s.push(chars[0]);
                s.extend(std::iter::repeat('*').take(chars.len() - 1));
                s
            } else {
                // Latin names: keep the first letter of each word
                value.split(' ').map(|w| {
                    let mut it = w.chars();
                    match it.next() {
                        Some(f) => format!("{}{}", f, "*".repeat(it.count())),
                        None => String::new(),
                    }
                }).collect::<Vec<_>>().join(" ")
            }
        }
        "ADDRESS" => {
            let keep = (chars.len() / 3).min(6);
            let mut s: String = chars.iter().take(keep).collect();
            s.push_str("***");
            s
        }
        _ => {
            if chars.len() <= 4 {
                "*".repeat(chars.len())
            } else {
                keep_edges(&chars, 1, 1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn examples_from_spec() {
        assert_eq!(mask_value("PHONE_NUMBER", "13800138000"), "138****8000");
        assert_eq!(mask_value("PHONE_NUMBER", "+86 138 0013 8000"), "+86 138 **** 8000");
        assert_eq!(mask_value("EMAIL_ADDRESS", "zhangsan@example.com"), "z***@example.com");
        assert_eq!(redact_label("API_KEY"), "[REDACTED_API_KEY]");
        assert_eq!(redact_label("BANK_CARD"), "[REDACTED_BANK_CARD]");
        assert_eq!(mask_value("PERSON", "张三"), "张*");
        assert_eq!(mask_value("BANK_CARD", "6222021234567890123"), "***************0123");
        assert_eq!(mask_value("CN_ID_CARD", "11010119900307002X"), "110***********002X");
    }
    #[test]
    fn never_reveals_more_than_half() {
        let m = mask_value("OTHER", "abcdef");
        assert_eq!(m.chars().filter(|c| *c != '*').count(), 2);
        assert_eq!(mask_value("OTHER", "ab"), "**");
    }
}
