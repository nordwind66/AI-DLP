//! Deterministic validators (checksums, structure, classification). These are what turns a
//! "looks like" pattern into a high-confidence finding and keeps false positives down.
use crate::model::ValidatorDef;
use base64::Engine;

#[derive(Debug, Clone)]
pub enum Validator {
    Luhn { min_len: usize, max_len: usize },
    CnIdCard,
    CnMobile,
    CnUscc,
    CnPostal,
    CnName,
    /// number of digits within [min,max] (separators ignored)
    DigitCount { min: usize, max: usize },
    /// Luhn + known card brand prefix/length (Visa, MC, Amex, JCB, Discover, Diners). UnionPay (62..) is
    /// deliberately excluded: it is handled by `bank-card-cn`, which requires banking context.
    CardBrand,
    Ipv4Private,
    Ipv4Public,
    Jwt,
    Iban,
    /// Reject degenerate values: all same char, strictly sequential, or very low variety.
    NotTrivial { min_distinct: usize },
    EntropyMin(f64),
    MinLen(usize),
    /// Value must contain at least one digit and one letter (api-key-ish).
    MixedAlnum,
    /// Reject values that are an obvious placeholder (`xxxx`, `your_api_key`, `<token>` ...).
    NotPlaceholder,
    /// Structural flag, not a value check: the match must not touch another ASCII digit. Unlike `\b`
    /// it still matches when letters / underscores are glued to the number (`tel13800138000`).
    /// Evaluated by the scanner, which sees the surrounding text.
    DigitBoundary,
}

#[derive(Debug, Clone)]
pub struct CompiledValidator {
    pub v: Validator,
    /// check against "secret" (default) or whole "match"
    pub on_match: bool,
}

pub fn parse(def: &ValidatorDef) -> Result<CompiledValidator, String> {
    let p = &def.params;
    let geti = |k: &str, d: i64| p.get(k).and_then(|x| x.as_i64()).unwrap_or(d);
    let on_match = p.get("target").and_then(|x| x.as_str()) == Some("match");
    let v = match def.name.as_str() {
        "luhn" => Validator::Luhn { min_len: geti("min_len", 12) as usize, max_len: geti("max_len", 19) as usize },
        "cn_id_card" => Validator::CnIdCard,
        "cn_mobile" => Validator::CnMobile,
        "cn_uscc" => Validator::CnUscc,
        "cn_postal" => Validator::CnPostal,
        "cn_name" => Validator::CnName,
        "digit_count" => Validator::DigitCount { min: geti("min", 8) as usize, max: geti("max", 15) as usize },
        "card_brand" => Validator::CardBrand,
        "ipv4_private" => Validator::Ipv4Private,
        "ipv4_public" => Validator::Ipv4Public,
        "jwt" => Validator::Jwt,
        "iban" => Validator::Iban,
        "not_trivial" => Validator::NotTrivial { min_distinct: geti("min_distinct", 4) as usize },
        "entropy_min" => Validator::EntropyMin(p.get("min").and_then(|x| x.as_f64()).unwrap_or(3.0)),
        "min_len" => Validator::MinLen(geti("min", 8) as usize),
        "mixed_alnum" => Validator::MixedAlnum,
        "not_placeholder" => Validator::NotPlaceholder,
        "digit_boundary" => Validator::DigitBoundary,
        other => return Err(format!("unknown validator '{other}'")),
    };
    Ok(CompiledValidator { v, on_match })
}

impl CompiledValidator {
    pub fn check(&self, secret: &str, whole: &str) -> bool {
        let s = if self.on_match { whole } else { secret };
        self.v.check(s)
    }
}

impl Validator {
    pub fn check(&self, s: &str) -> bool {
        match self {
            Validator::Luhn { min_len, max_len } => luhn(s, *min_len, *max_len),
            Validator::CnIdCard => cn_id_card(s),
            Validator::CnMobile => cn_mobile(s),
            Validator::CnUscc => cn_uscc(s),
            Validator::CnPostal => cn_postal(s),
            Validator::CnName => cn_name(s),
            Validator::DigitCount { min, max } => {
                let n = s.chars().filter(|c| c.is_ascii_digit()).count();
                n >= *min && n <= *max
            }
            Validator::CardBrand => card_brand(s),
            Validator::Ipv4Private => ipv4(s).map(is_private_v4).unwrap_or(false),
            Validator::Ipv4Public => ipv4(s).map(|o| !is_private_v4(o) && !is_reserved_v4(o)).unwrap_or(false),
            Validator::Jwt => jwt(s),
            Validator::Iban => iban(s),
            Validator::NotTrivial { min_distinct } => not_trivial(s, *min_distinct),
            Validator::EntropyMin(m) => shannon_entropy(s) > *m,
            Validator::MinLen(n) => s.chars().count() >= *n,
            Validator::MixedAlnum => s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| c.is_ascii_alphabetic()),
            Validator::NotPlaceholder => !is_placeholder(s),
            Validator::DigitBoundary => true,
        }
    }
}

/// Shannon entropy exactly as gitleaks computes it (`detect/utils.go: shannonEntropy`):
/// per-rune frequency, but normalised by the **byte** length of the string.
pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let inv = 1.0 / data.len() as f64;
    let mut ent = 0.0;
    if data.is_ascii() {
        let mut counts = [0u32; 128];
        for b in data.bytes() {
            counts[b as usize] += 1;
        }
        for &c in counts.iter().filter(|&&c| c > 0) {
            let f = c as f64 * inv;
            ent -= f * f.log2();
        }
    } else {
        let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
        for ch in data.chars() {
            *counts.entry(ch).or_insert(0) += 1;
        }
        for &c in counts.values() {
            let f = c as f64 * inv;
            ent -= f * f.log2();
        }
    }
    ent
}

fn digits_only(s: &str) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '0'..='9' => v.push(c as u8 - b'0'),
            ' ' | '-' => {}
            _ => return None,
        }
    }
    Some(v)
}

pub fn luhn(s: &str, min_len: usize, max_len: usize) -> bool {
    let Some(d) = digits_only(s) else { return false };
    if d.len() < min_len || d.len() > max_len {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &x) in d.iter().rev().enumerate() {
        let mut v = x as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

fn valid_date(y: u32, m: u32, d: u32) -> bool {
    if !(1900..=2100).contains(&y) || !(1..=12).contains(&m) || d < 1 {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => if leap { 29 } else { 28 },
    };
    d <= dim
}

/// China resident ID (GB 11643-1999): region + birth date + ISO 7064 MOD 11-2 check digit.
pub fn cn_id_card(s: &str) -> bool {
    let b: Vec<char> = s.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    if b.len() != 18 {
        return false;
    }
    if !b[..17].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let province: u32 = b[..2].iter().collect::<String>().parse().unwrap_or(0);
    const PROV: [u32; 34] = [11, 12, 13, 14, 15, 21, 22, 23, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46, 50, 51, 52, 53, 54, 61, 62, 63, 64, 65, 71, 81, 82];
    if !PROV.contains(&province) {
        return false;
    }
    let y: u32 = b[6..10].iter().collect::<String>().parse().unwrap_or(0);
    let m: u32 = b[10..12].iter().collect::<String>().parse().unwrap_or(0);
    let d: u32 = b[12..14].iter().collect::<String>().parse().unwrap_or(0);
    if !valid_date(y, m, d) {
        return false;
    }
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CODE: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let sum: u32 = b[..17].iter().zip(W.iter()).map(|(c, w)| c.to_digit(10).unwrap() * w).sum();
    CODE[(sum % 11) as usize] == b[17].to_ascii_uppercase()
}

pub fn card_brand(s: &str) -> bool {
    let Some(d) = digits_only(s) else { return false };
    let n = d.len();
    let p = |k: usize| d.iter().take(k).fold(0u32, |a, &x| a * 10 + x as u32);
    let ok = match () {
        _ if d[0] == 4 => n == 13 || n == 16 || n == 19,
        _ if (51..=55).contains(&p(2)) || (2221..=2720).contains(&p(4)) => n == 16,
        _ if p(2) == 34 || p(2) == 37 => n == 15,
        _ if (3528..=3589).contains(&p(4)) => (16..=19).contains(&n),
        _ if p(4) == 6011 || p(2) == 65 || (644..=649).contains(&p(3)) => n == 16,
        _ if (300..=305).contains(&p(3)) || p(2) == 36 || p(2) == 38 => n == 14 || n == 16,
        _ => false,
    };
    ok && luhn(s, 13, 19)
}

pub fn cn_mobile(s: &str) -> bool {
    // fold full-width digits / plus / hyphen (１３８…, ＋８６, －) to ASCII
    let t: String = s
        .chars()
        .map(|c| match c {
            '０'..='９' => char::from(b'0' + (c as u32 - '０' as u32) as u8),
            '＋' => '+',
            '－' => '-',
            c => c,
        })
        .filter(|c| !matches!(c, ' ' | '-'))
        .collect();
    let t = t.strip_prefix("+86").or_else(|| t.strip_prefix("86")).unwrap_or(&t);
    let b = t.as_bytes();
    if b.len() != 11 || b[0] != b'1' || !b.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // MIIT-allocated mobile prefixes: 13x, 145 147 149, 15x (not 154), 162 165 166 167, 17x (not 179),
    // 18x, 19x (not 194). Anything else (e.g. 11x, 12x, 161) is not a mobile number.
    let p3 = &t[..3];
    let ok = match &p3[..2] {
        "13" | "18" => true,
        "14" => matches!(&p3[2..], "5" | "7" | "9"),
        "15" => &p3[2..] != "4",
        "16" => matches!(&p3[2..], "2" | "5" | "6" | "7"),
        "17" => &p3[2..] != "9",
        "19" => &p3[2..] != "4",
        _ => false,
    };
    if !ok {
        return false;
    }
    // reject runs like 13800000000 / 11111111111
    not_trivial_impl(&t[3..], 3)
}

/// Unified Social Credit Code (GB 32100-2015), 18 chars, mod-31 check.
pub fn cn_uscc(s: &str) -> bool {
    const CHARS: &str = "0123456789ABCDEFGHJKLMNPQRTUWXY";
    const W: [u32; 17] = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28];
    let b: Vec<char> = s.to_ascii_uppercase().chars().collect();
    if b.len() != 18 {
        return false;
    }
    let mut sum = 0;
    for i in 0..17 {
        let Some(p) = CHARS.find(b[i]) else { return false };
        sum += p as u32 * W[i];
    }
    let check = (31 - sum % 31) % 31;
    CHARS.chars().nth(check as usize) == Some(b[17])
}

pub fn cn_postal(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 6 && b.iter().all(|c| c.is_ascii_digit()) && (b'0'..=b'8').contains(&b[0]) && {
        let p = (b[0] - b'0') * 10 + (b[1] - b'0');
        (1..=86).contains(&p) && not_trivial_impl(s, 3)
    }
}

const SURNAMES: &str = "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾萧田董潘袁蔡蒋余于杜叶程魏苏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁冉骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉缪简车项连芦麦褚娄窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边卞姬师和仇栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩明佘池查麻苑迟邝";
const COMPOUND: [&str; 24] = ["欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "尉迟", "公孙", "慕容", "长孙", "宇文", "司徒", "夏侯", "轩辕", "令狐", "端木", "独孤", "南宫", "西门", "百里", "呼延", "澹台", "公冶", "太史"];

/// A plausible Chinese personal name: 2-4 Han chars (optionally with '·'), starting with a known
/// surname. This is a *filter* for contextual rules, never a standalone detector.
pub fn cn_name(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let han = |c: &char| ('\u{4e00}'..='\u{9fff}').contains(c);
    if !(2..=4).contains(&chars.len()) && !(chars.len() <= 8 && chars.contains(&'·')) {
        return false;
    }
    if !chars.iter().all(|c| han(c) || *c == '·') {
        return false;
    }
    if COMPOUND.iter().any(|c| s.starts_with(c)) {
        return true;
    }
    SURNAMES.contains(chars[0])
}

fn ipv4(s: &str) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n >= 4 || part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        o[n] = part.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
        n += 1;
    }
    (n == 4).then_some(o)
}
fn is_private_v4(o: [u8; 4]) -> bool {
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)
}
fn is_reserved_v4(o: [u8; 4]) -> bool {
    o[0] == 0 || o[0] == 127 || o[0] >= 224 || (o[0] == 192 && o[1] == 0 && o[2] == 2) || (o[0] == 198 && o[1] == 51 && o[2] == 100) || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

pub fn jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    let dec = |p: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok();
    let Some(h) = dec(parts[0]) else { return false };
    let Some(pl) = dec(parts[1]) else { return false };
    let hj: serde_json::Value = match serde_json::from_slice(&h) {
        Ok(v) => v,
        Err(_) => return false,
    };
    hj.get("alg").is_some() && serde_json::from_slice::<serde_json::Value>(&pl).map(|v| v.is_object()).unwrap_or(false)
}

pub fn iban(s: &str) -> bool {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    if t.len() < 15 || t.len() > 34 || !t.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let rot = format!("{}{}", &t[4..], &t[..4]);
    let mut rem = 0u32;
    for c in rot.chars() {
        let v = if c.is_ascii_digit() { c.to_digit(10).unwrap() } else { c as u32 - 'A' as u32 + 10 };
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

fn not_trivial_impl(s: &str, min_distinct: usize) -> bool {
    let mut seen = std::collections::HashSet::new();
    for c in s.chars() {
        seen.insert(c);
    }
    if seen.len() < min_distinct {
        return false;
    }
    // strictly ascending / descending digit run
    let d: Vec<i32> = s.chars().filter_map(|c| c.to_digit(10)).map(|x| x as i32).collect();
    if d.len() == s.chars().count() && d.len() >= 6 {
        let asc = d.windows(2).all(|w| w[1] == w[0] + 1);
        let desc = d.windows(2).all(|w| w[1] == w[0] - 1);
        if asc || desc {
            return false;
        }
    }
    true
}
pub fn not_trivial(s: &str, min_distinct: usize) -> bool {
    not_trivial_impl(s, min_distinct)
}

/// Obvious documentation placeholders (`YOUR_API_KEY`, `<token>`, `xxxx`, `changeme`, `${SECRET}`).
/// Marker words must be whole tokens (split on non-alphanumerics): `MyExamplePass1` and the host
/// `db01.corp.example` are NOT placeholders, `your_api_key` and `sample-token` are.
pub fn is_placeholder(s: &str) -> bool {
    const STRONG: [&str; 7] = ["your", "placeholder", "redacted", "todo", "insert", "replace", "dummy"];
    const WEAK: [&str; 4] = ["example", "sample", "test", "fake"];
    let l = s.to_ascii_lowercase();
    let tokens: Vec<&str> = l.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).collect();
    if tokens.iter().any(|t| STRONG.contains(t) || t.starts_with("changeme")) {
        return true;
    }
    // weak markers only count in short values; inside a long random-looking secret they are noise
    let alnum = l.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    if alnum <= 24 && tokens.iter().any(|t| WEAK.contains(t)) {
        return true;
    }
    let b = l.as_bytes();
    let mut run = 1;
    for i in 1..b.len() {
        run = if b[i] == b[i - 1] && matches!(b[i], b'x' | b'*' | b'#') { run + 1 } else { 1 };
        if run >= 4 {
            return true;
        }
    }
    (l.starts_with('<') && l.ends_with('>')) || (l.starts_with("${") && l.ends_with('}')) || (l.starts_with("{{") && l.ends_with("}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn id_card_checksum() {
        // synthetic: region 110101, birth 19900307, seq 002 -> computed check digit
        let base = "11010119900307002";
        const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
        const CODE: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
        let sum: u32 = base.chars().zip(W).map(|(c, w)| c.to_digit(10).unwrap() * w).sum();
        let ok = format!("{}{}", base, CODE[(sum % 11) as usize]);
        assert!(cn_id_card(&ok));
        let bad_check = format!("{}{}", base, if CODE[(sum % 11) as usize] == '0' { '1' } else { '0' });
        assert!(!cn_id_card(&bad_check));
        assert!(!cn_id_card("110101199013070021")); // month 13
        assert!(!cn_id_card("990101199003070025")); // bad province
    }
    #[test]
    fn luhn_cards() {
        assert!(luhn("4111 1111 1111 1111", 12, 19));
        assert!(!luhn("4111 1111 1111 1112", 12, 19));
        assert!(!luhn("0000000000000000", 12, 19));
    }
    #[test]
    fn card_brands() {
        assert!(card_brand("4111 1111 1111 1111"));
        assert!(card_brand("5500 0000 0000 0004"));
        assert!(card_brand("3782 822463 10005"));
        assert!(!card_brand("1234 5678 9012 3452")); // passes Luhn but unknown brand
        assert!(!card_brand("4111 1111 1111 1112"));
    }
    #[test]
    fn id_card_with_separators() {
        assert!(cn_id_card("11010119900307 0027") == cn_id_card("110101199003070027"));
    }
    #[test]
    fn mobile() {
        assert!(cn_mobile("13800138000"));
        assert!(cn_mobile("+86 138-0013-8000"));
        assert!(!cn_mobile("12800138000"));
        assert!(!cn_mobile("16180665592"), "161 is not an allocated prefix");
        assert!(!cn_mobile("15400138000") && !cn_mobile("17900138000") && !cn_mobile("19400138000"));
        assert!(cn_mobile("16688778899") && cn_mobile("14500138000") && cn_mobile("19912349678"));
        assert!(!cn_mobile("13800000000"));
    }
    #[test]
    fn names() {
        assert!(cn_name("张三") && cn_name("欧阳娜娜") && cn_name("王小明"));
        assert!(!cn_name("手机号") && !cn_name("我们去") && !cn_name("张"));
    }
    #[test]
    fn uscc_and_ip() {
        assert!(Validator::Ipv4Private.check("192.168.1.10"));
        assert!(!Validator::Ipv4Private.check("8.8.8.8"));
        assert!(!Validator::Ipv4Private.check("192.168.01.10"));
        assert!(Validator::Ipv4Public.check("8.8.8.8"));
        assert!(!Validator::Ipv4Public.check("127.0.0.1"));
    }
    #[test]
    fn placeholder_tokens() {
        for p in ["YOUR_API_KEY_HERE", "<your-token>", "sk-xxxxxxxxxxxxxxxx", "changeme123", "${SECRET_FROM_ENV}", "sample-token", "********", "example"] {
            assert!(is_placeholder(p), "{p}");
        }
        for p in ["MyExamplePass1", "Zq8vN3pL2xK9", "AKIAZ3XQKVN5TLWM7EPD", "contest2024Key"] {
            assert!(!is_placeholder(p), "{p}");
        }
    }
    #[test]
    fn entropy_matches_gitleaks_formula() {
        assert!((shannon_entropy("aaaa") - 0.0).abs() < 1e-9);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }
    #[test]
    fn jwt_structure() {
        // header {"alg":"HS256","typ":"JWT"} payload {"sub":"1234567890"}
        assert!(jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"));
        assert!(!jwt("aaa.bbb.ccc"));
    }
}
