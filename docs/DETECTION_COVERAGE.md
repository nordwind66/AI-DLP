# What is detected (Chinese-first coverage)

Detection is deterministic: regular expressions, checksums (Luhn, ID-card mod 11, USCC), prefix tables, context words and
dictionaries; no ML model. "Default action" is what the `default` policy does; every action is changeable per policy
and per request. The matrix below is executed on every `cargo test` by `crates/dlp-engine/tests/zh_coverage.rs`
(34 Chinese cases: detected **and** the raw value is gone from the sanitized text) plus a near-miss test.

| Data | Recognised forms | Needs context word? | Default action |
|---|---|---|---|
| **Mobile phone** (CN) | `13800138000`, `138 0013 8000`, `138-0013-8000`, `+86…`, `86-…`, full-width digits `１３８…`, glued to Chinese text, lists separated by `、` | no (real MIIT prefixes only; labels such as 流水号/订单号/时间戳 suppress) | MASK `138****8000` |
| **Landline** | `010-62345678`, `(010)62345678`, `（010）62345678` | no | MASK |
| **International phone** | `+1 212-555-0198` etc. (Presidio / libphonenumber, 13 regions) | no | MASK |
| **Bank card** | 16–19 digits with Luhn: with a context word (银行卡/卡号/储蓄卡/转账…) any prefix; **UnionPay `62…` also with no context**; Visa/MC/Amex/JCB/Discover via the credit-card rule; digit groups with spaces or dashes | context for non-62 numbers | REDACT |
| **Labelled account number** | after 银行卡号/卡号/银行账号/对公账户/账号/账户 even when the checksum is wrong (typos) | label | REDACT |
| **E-mail** | normal, glued to Chinese text, inside `<>`, full-width `＠` | no | MASK `z***@example.com` |
| **ID card** (18-digit) | with mod-11 check digit, `x`/`X`, spaces or dashes inside | no | REDACT |
| **Unified social credit code** | 18 chars with checksum | no | AUDIT (company identifier, public) |
| **Passport / HK-Macao-Taiwan permit** | E/G/D/S/P/H + digits with 护照 context; H/M + 8–10 digits with 通行证/港澳 context | yes | REDACT |
| **License plate** | `京A12345`, 8-character new-energy `粤BD12345` | no | MASK |
| **Address** | province/municipality-anchored (`北京市海淀区…`) | anchor | MASK |
| **API keys / tokens** | the 223 Gitleaks rules (AWS, GitHub, Aliyun `LTAI…`, Tencent `AKID…`, Slack, Stripe, JWT, …); **unlabelled `sk-…` keys** (OpenAI-compatible vendors: DeepSeek, Moonshot, Qwen…); `api_key=…`, `X-Api-Key:`, `Authorization: Bearer …`, URL `access_token=…`; **Chinese labels** 密钥/秘钥/令牌/访问令牌 and `AppSecret`, `app_secret`, `AccessKey`, `AK:`/`SK:`, `API Key：` with a value | value must look random (entropy, mixed characters, not a placeholder) | REDACT |
| **Password** | `密码是…`, `口令：…`, `password=…` | label | REDACT |
| **Private key** | PEM blocks (RSA/EC/OPENSSH/PGP) | no | REDACT |
| **DB connection string** | `jdbc:mysql://user:pw@host/db`, `postgres://`, `mongodb+srv://`, `redis://`… (placeholders like `your_password` allowed) | no | REDACT |
| **Internal assets** | private IPv4, `*.internal/.corp/.lan` domains, customer dictionaries | no | AUDIT / REDACT |
| **Person name** | after a label (`姓名：`, `联系人：`…), possessive (`张三的手机号`), dictionary entries; surname + shape validation | label / pattern / dictionary | ANONYMIZE |
| **Company name** | dictionary entries only | dictionary | per dictionary |

## Not detected (be aware)

* **Free-text person and company names without a label** ("昨天王小明和刘芳开了会", "客户是北京字节跳动科技有限公司")
  and free-form addresses without a province anchor. No model is used by decision; add names to a dictionary
  (hot-reloadable) or use labelled patterns. See ACCURACY_REPORT.md (Chinese PERSON recall 0.57 on the synthetic set).
* Digits inside a longer digit run (`913800138000`, 20-digit order numbers) are not phone numbers; a bank card needs a
  context word unless it is UnionPay (`62…`).
* Wrong-checksum ID cards and unlabelled Luhn-invalid card numbers (by design, to avoid false positives).
* Obfuscated values (`1 3 8 0 0 1 3 8 0 0 0`, `一三八…`, base64/hex-encoded secrets).
* Secret formats with no prefix, label or entropy signal (a bare random string in prose).

## Adding your own

Rules live in SQLite (`rules`, `dictionaries`, `policies` tables), can be changed through the CLI/API and hot-reloaded
without a restart; an invalid rule never replaces the running rule set (DATABASE.md, API.md).
