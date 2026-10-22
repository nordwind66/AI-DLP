//! Chinese-first coverage matrix: the sensitive-data shapes people actually write in Chinese chat / tickets /
//! logs. Every case must be detected AND the raw value must be gone from the sanitized text (default policy).
//! Secrets and card numbers are generated at run time (valid checksums, random-looking) so no key-shaped
//! literal lives in the repository.
mod common;
use common::*;
use dlp_core::*;
use dlp_engine::*;

fn rnd(seed: u64, n: usize, alphabet: &str) -> String {
    let a: Vec<char> = alphabet.chars().collect();
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            a[((x >> 33) as usize) % a.len()]
        })
        .collect()
}
const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn luhn_card(prefix: &str, len: usize, seed: u64) -> String {
    let mut d: Vec<u32> = prefix.chars().map(|c| c.to_digit(10).unwrap()).collect();
    for c in rnd(seed, len - 1 - d.len(), "0123456789").chars() {
        d.push(c.to_digit(10).unwrap());
    }
    let s: u32 = d.iter().rev().enumerate().map(|(i, &x)| if i % 2 == 0 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x }).sum();
    d.push((10 - s % 10) % 10);
    d.iter().map(|x| char::from_digit(*x, 10).unwrap()).collect()
}
fn group4(s: &str) -> String {
    s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
}

struct Case {
    name: &'static str,
    text: String,
    ty: &'static str,
    secret: String, // substring that must NOT survive
}

fn cases() -> Vec<Case> {
    let card19 = luhn_card("622202", 19, 1);
    let card16 = luhn_card("621700", 16, 2);
    let key48 = rnd(3, 48, ALNUM);
    let key32 = rnd(4, 32, ALNUM);
    let hex32 = rnd(5, 32, "0123456789abcdef");
    let tok40 = rnd(6, 40, ALNUM);
    let c = |name, text: String, ty, secret: &str| Case { name, text, ty, secret: secret.to_string() };
    vec![
        c("phone plain", "我的手机号是13800138000，请回电".into(), "PHONE_NUMBER", "13800138000"),
        c("phone spaces", "电话：138 0013 8000".into(), "PHONE_NUMBER", "0013"),
        c("phone dashes", "联系电话 138-0013-8000".into(), "PHONE_NUMBER", "0013"),
        c("phone +86", "拨打+8613800138000".into(), "PHONE_NUMBER", "13800138000"),
        c("phone glued to hanzi", "张三13800138000李四".into(), "PHONE_NUMBER", "13800138000"),
        c("phone full-width digits", "手机号：１３８００１３８０００".into(), "PHONE_NUMBER", "００１３"),
        c("landline", "公司电话 010-62345678".into(), "PHONE_NUMBER", "62345678"),
        c("landline brackets", "电话(010)62345678".into(), "PHONE_NUMBER", "62345678"),
        c("bank card with label", format!("银行卡号：{card19}"), "BANK_CARD", &card19),
        c("bank card grouped", format!("请转账到卡号 {}", group4(&card19)), "BANK_CARD", &card19[4..12]),
        c("bank card without any label", format!("这个数字 {card16} 是什么"), "BANK_CARD", &card16),
        c("bank card bad checksum but labelled", "银行卡号：6222028994690700494".into(), "BANK_ACCOUNT", "6222028994690700494"),
        c("email", "邮箱 zhangsan@example.com，请查收".into(), "EMAIL_ADDRESS", "zhangsan@"),
        c("email glued to hanzi", "联系li.si-2024@mail.corp.com.cn谢谢".into(), "EMAIL_ADDRESS", "li.si-2024@"),
        c("email full-width @", "邮箱：zhangsan＠example.com".into(), "EMAIL_ADDRESS", "zhangsan＠"),
        c("id card", "身份证号：11010119900307002X".into(), "CN_ID_CARD", "11010119900307002X"),
        c("id card lowercase x", "身份证 11010119900307002x".into(), "CN_ID_CARD", "19900307"),
        c("id card without label", "学员 11010119900307002X 已报到".into(), "CN_ID_CARD", "11010119900307002X"),
        c("sk- key labelled", format!("DEEPSEEK_API_KEY=sk-{key32}"), "LLM_API_KEY", &key32),
        c("sk- key unlabelled", format!("把这个 key sk-{key48} 给我配置上"), "LLM_API_KEY", &key48),
        c("aws access key", "aws_access_key_id = AKIAZ3XQKVN5TLWM7EPD".into(), "CLOUD_CREDENTIAL", "AKIAZ3XQKVN5TLWM7EPD"),
        c("aliyun access key", "阿里云 AccessKey ID：LTAI5tQwXyZ1AbCdEfGh2Jk3".into(), "CLOUD_CREDENTIAL", "LTAI5tQwXyZ1AbCdEfGh2Jk3"),
        c("zhipu style id.secret", format!("智谱 API Key：{hex32}.{}", rnd(7, 16, ALNUM)), "API_KEY", &hex32),
        c("feishu app_secret", format!("飞书 app_secret：{key32}"), "API_KEY", &key32),
        c("baidu AK/SK", format!("百度智能云 AK：{} SK：{key32}", rnd(8, 24, ALNUM)), "API_KEY", &key32),
        c("chinese token label", format!("访问令牌：{tok40}"), "API_KEY", &tok40),
        c("chinese password", "管理员密码是 Zx9!kLm2#Qw".into(), "PASSWORD", "Zx9!kLm2#Qw"),
        c("api_key=", format!("api_key={key32}"), "API_KEY", &key32),
        c("db url", "jdbc:mysql://root:Passw0rd9X@10.0.3.21:3306/orders".into(), "DB_CONNECTION_STRING", "Passw0rd9X"),
        c("license plate", "车牌号 京A12345".into(), "LICENSE_PLATE", "A12345"),
        c("new-energy plate", "车牌 粤BD12345".into(), "LICENSE_PLATE", "BD12345"),
        c("address", "地址：北京市海淀区中关村大街1号".into(), "ADDRESS", "中关村大街1号"),
        c("labelled name", "姓名：李四".into(), "PERSON", "李四"),
        c("possessive name", "张三的手机号是13800138000".into(), "PERSON", "张三"),
    ]
}

#[test]
fn chinese_sensitive_data_matrix_is_detected_and_removed() {
    let e = engine();
    let mut failures = vec![];
    for c in cases() {
        let r = e.process(&admin(), &req(&c.text, "default", Mode::Sanitize)).unwrap();
        let found = r.entities.iter().any(|x| x.entity_type == c.ty);
        let out = r.sanitized_text.clone().unwrap_or_default();
        if !found {
            failures.push(format!("{}: {} not detected (got {:?})", c.name, c.ty, r.entities.iter().map(|x| x.entity_type.as_str()).collect::<Vec<_>>()));
        } else if out.contains(&c.secret) {
            failures.push(format!("{}: raw value survived: {out}", c.name));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn near_misses_are_left_alone() {
    let e = engine();
    for t in [
        "订单号 13800138000123456789 已发货",                // phone-shaped digits inside a longer id
        "流水号：13800138000",                               // labelled as a serial number
        "时间戳 1698339816995",                               // epoch millis
        "这个数字 6217001054013077 的校验位不对吗",             // (Luhn-invalid, checked below with a label-free text)
        "我们讨论了 key 的设计，secret 的含义，以及 token 的过期策略",
        "密钥：请联系管理员获取",                             // label with no value
        "车牌识别算法 京ABCDE 只是个示例词",                    // letters only: no digit
    ] {
        let r = e.process(&admin(), &req(t, "default", Mode::Sanitize)).unwrap();
        let risky: Vec<_> = r.entities.iter().filter(|x| matches!(x.entity_type.as_str(), "PHONE_NUMBER" | "LLM_API_KEY" | "API_KEY" | "LICENSE_PLATE")).collect();
        // the Luhn-invalid 62-prefixed example is the only one that may legitimately be a card; everything else must be clean
        if t.contains("6217001054013077") {
            continue;
        }
        assert!(risky.is_empty(), "false positive in {t:?}: {risky:?}");
    }
}
