"""Deterministic generator for the accuracy test set (seed fixed). Every value is SYNTHETIC:
 - names are generic placeholders, emails use example.* domains, phones are made-up numbers,
 - ID cards / cards are computed (valid checksums) from made-up bodies,
 - secrets are random strings in vendor *formats* - none of them is, or was, a live credential.
Annotation syntax inside templates:  {{TYPE|text}}  -> gold entity of group TYPE over `text`.
Output: dataset.jsonl with {id, category, lang, text, entities:[{type,start,end}]} (start/end = code points).
"""
import json, random, re, string, base64, os, hashlib

R = random.Random(20261021)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset.jsonl")

SUR = list("王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾萧田董")
GIVEN = ["伟", "芳", "娜", "敏", "静", "磊", "洋", "艳", "勇", "军", "杰", "娟", "涛", "明", "超", "秀英", "丽", "强", "霞", "平", "刚", "小明", "子轩", "思远", "浩然", "雨桐", "欣怡", "梓涵", "宇航", "佳琪"]
EN_FIRST = ["Alice", "Bob", "Carol", "David", "Emma", "Frank", "Grace", "Henry", "Irene", "Jack", "Karen", "Liam", "Maria", "Noah", "Olivia", "Peter", "Quinn", "Rachel", "Samuel", "Tina"]
EN_LAST = ["Johnson", "Smith", "Williams", "Brown", "Jones", "Miller", "Davis", "Garcia", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White"]
CN_CITIES = [("北京市", "海淀区", "中关村大街"), ("上海市", "浦东新区", "世纪大道"), ("广东省深圳市", "南山区", "科技园路"), ("浙江省杭州市", "西湖区", "文三路"), ("四川省成都市", "武侯区", "人民南路"), ("江苏省南京市", "鼓楼区", "中山路"), ("湖北省武汉市", "洪山区", "珞喻路"), ("陕西省西安市", "雁塔区", "科技路")]
COMPANIES_CN = ["腾讯科技有限公司", "阿里巴巴集团", "华为技术有限公司", "北京字节跳动科技有限公司", "中国工商银行", "小米科技有限责任公司", "京东集团", "美团点评"]
COMPANIES_EN = ["Acme Corporation", "Globex Inc.", "Initech LLC", "Umbrella Corp", "Stark Industries", "Wayne Enterprises"]
PROJECTS = ["夜莺计划", "Project Nightingale"]
SYSTEMS = ["Orion-CRM"]

def cn_name(): return R.choice(SUR) + R.choice(GIVEN)
def en_name(): return f"{R.choice(EN_FIRST)} {R.choice(EN_LAST)}"
def phone():
    return R.choice(["138", "139", "150", "158", "176", "186", "199", "135", "182"]) + "".join(R.choice("0123456789") for _ in range(8))
def phone_fmt():
    p = phone(); return R.choice([p, f"{p[:3]} {p[3:7]} {p[7:]}", f"{p[:3]}-{p[3:7]}-{p[7:]}", f"+86 {p}"])
def email():
    return R.choice(["zhang.wei", "li_na", "wang123", "sales", "hr.team", "alice", "bob.smith", "support", "dev-ops", "test.user"]) + str(R.randint(1, 99)) + "@" + R.choice(["example.com", "example.org", "mail.example.net", "corp.example.cn"])
def id_card():
    prov = R.choice(["110101", "310104", "440305", "330106", "510107", "320106", "420111", "610113"])
    y = R.randint(1960, 2003); m = R.randint(1, 12); d = R.randint(1, 28)
    body = f"{prov}{y}{m:02d}{d:02d}{R.randint(0, 999):03d}"
    W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]; C = "10X98765432"
    return body + C[sum(int(a) * b for a, b in zip(body, W)) % 11]
def bad_id_card():
    v = id_card(); last = v[-1]
    return v[:-1] + ("0" if last != "0" else "1")
def luhn_complete(body):
    s = 0
    for i, c in enumerate(reversed(body)):
        d = int(c)
        if i % 2 == 0:
            d *= 2
            if d > 9: d -= 9
        s += d
    return body + str((10 - s % 10) % 10)
def credit_card(): return luhn_complete(R.choice(["4", "51", "55", "37"]) + "".join(R.choice("0123456789") for _ in range({"4": 14, "51": 13, "55": 13, "37": 12}[R.choice(["4"])] ) ))
def visa():
    body = "4" + "".join(R.choice("0123456789") for _ in range(14)); c = luhn_complete(body)
    return R.choice([c, " ".join(c[i:i+4] for i in range(0, 16, 4)), "-".join(c[i:i+4] for i in range(0, 16, 4))])
def unionpay():
    body = "62" + "".join(R.choice("0123456789") for _ in range(16)); c = luhn_complete(body)
    return R.choice([c, " ".join([c[:4], c[4:8], c[8:12], c[12:16], c[16:]])])
def rnd(alpha, n): return "".join(R.choice(alpha) for _ in range(n))
AN = string.ascii_letters + string.digits
def aws_key(): return "AKIA" + rnd("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
def gh_token(): return "ghp_" + rnd(AN, 36)
def stripe_key(): return "sk_live_" + rnd(AN, 24)
def slack_bot(): return f"xoxb-{rnd(string.digits, 11)}-{rnd(string.digits, 12)}-{rnd(AN, 24)}"
def openai_key(): return "sk-" + rnd(AN, 20) + "T3BlbkFJ" + rnd(AN, 20)
def anthropic_key(): return "sk-ant-api03-" + rnd(AN + "-_", 93) + "AA"
def hf_token(): return "hf_" + rnd(string.ascii_letters, 34)
def google_key(): return "AIza" + rnd(AN + "-_", 35)
def jwt():
    h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps({"sub": str(R.randint(10**9, 10**10)), "name": "tester", "iat": R.randint(1500000000, 1800000000)}).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.{rnd(AN + '-_', 43)}"
def pem():
    body = "\n".join(rnd(AN + "+/", 64) for _ in range(R.randint(6, 12)))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
def ip_int(): return R.choice([f"10.{R.randint(0,255)}.{R.randint(0,255)}.{R.randint(1,254)}", f"192.168.{R.randint(0,255)}.{R.randint(1,254)}", f"172.{R.randint(16,31)}.{R.randint(0,255)}.{R.randint(1,254)}"])
def hex_hash(n=32): return rnd("0123456789abcdef", n)
def pwd(): return rnd(AN, 12) + R.choice("!@#$")
def dbpass(): return rnd(AN, 14)

cases = []
def add(category, lang, template):
    ents = []; out = []; pos = 0
    for m in re.finditer(r"\{\{([A-Z_]+)\|(.*?)\}\}", template, flags=re.S):
        out.append(template[pos:m.start()]); start = sum(len(x) for x in out)
        out.append(m.group(2)); ents.append({"type": m.group(1), "start": start, "end": start + len(m.group(2))}); pos = m.end()
    out.append(template[pos:]); text = "".join(out)
    cases.append({"id": f"{category}-{len(cases):04d}", "category": category, "lang": lang, "text": text, "entities": ents})

# ---- normal chat (negatives) -----------------------------------------------------------------
CHAT_ZH = ["今天的会议安排在下午三点，请大家准时参加。", "帮我写一首关于春天的短诗。", "请解释一下什么是快速排序，并给出Python示例。", "晚上一起去吃火锅吧，我请客。", "这个周末天气不错，适合去爬山。", "麻烦把这份报告的摘要缩短到三百字以内。", "我想学习机器学习，应该从哪里开始？", "项目进度已经完成百分之八十，预计下周五上线。", "你觉得这个方案的主要风险是什么？", "把下面这段话翻译成英文：今天是个好日子。", "请总结一下《红楼梦》的主要人物关系。", "订单总共三件商品，满一百减二十。", "昨天的足球比赛真精彩，最后一分钟绝杀。", "请给我推荐几本适合初学者的数据库书籍。", "版本号是2.3.1，构建编号20240315，请更新文档。"]
CHAT_EN = ["Can you explain how a binary search tree works?", "Write a short poem about autumn leaves.", "Summarize the key differences between TCP and UDP.", "What is a good way to learn Rust in three months?", "Please translate this sentence into French: good morning, everyone.", "The meeting moved to Thursday at 3 pm, see you there.", "How do I reverse a linked list in Python?", "Give me five ideas for a team building event.", "The quarterly revenue grew by 12 percent compared to last year.", "Explain the difference between a process and a thread."]
for _ in range(40): add("chat", "zh", R.choice(CHAT_ZH) + R.choice(["", "谢谢！", "尽快回复。", ""]))
for _ in range(25): add("chat", "en", R.choice(CHAT_EN) + R.choice(["", " Thanks!", " Be concise."]))

# ---- Chinese PII -------------------------------------------------------------------------------
for _ in range(30):
    n, p = cn_name(), phone_fmt()
    add("pii_zh", "zh", R.choice([f"联系人：{{{{PERSON|{n}}}}}，手机号{{{{PHONE_NUMBER|{p}}}}}。", f"{{{{PERSON|{n}}}}}的手机号是{{{{PHONE_NUMBER|{p}}}}}。", f"请帮{{{{PERSON|{n}}}}}分析客户资料，他的电话是{{{{PHONE_NUMBER|{p}}}}}。", f"收件人：{{{{PERSON|{n}}}}} 联系电话：{{{{PHONE_NUMBER|{p}}}}}"]))
for _ in range(25):
    n, i = cn_name(), id_card()
    add("pii_zh", "zh", R.choice([f"员工{{{{PERSON|{n}}}}}的身份证号是{{{{CN_ID_CARD|{i}}}}}。", f"姓名：{{{{PERSON|{n}}}}}，身份证：{{{{CN_ID_CARD|{i}}}}}", f"请核对身份证号码 {{{{CN_ID_CARD|{i}}}}} 是否正确。"]))
for _ in range(20):
    c, d, s = R.choice(CN_CITIES); num = R.randint(1, 300)
    addr = f"{c}{d}{s}{num}号"
    n = cn_name()
    add("pii_zh", "zh", R.choice([f"{{{{PERSON|{n}}}}}住在{{{{ADDRESS|{addr}}}}}，请上门取件。", f"收货地址：{{{{ADDRESS|{addr}}}}}", f"公司地址是{{{{ADDRESS|{addr}{R.randint(2,30)}层}}}}。"]))
for _ in range(15):
    e, n = email(), cn_name()
    add("pii_zh", "zh", f"请把合同发给{{{{PERSON|{n}}}}}，邮箱 {{{{EMAIL_ADDRESS|{e}}}}}。")
for _ in range(15):
    n = cn_name(); card = unionpay()
    add("pii_zh", "zh", R.choice([f"请转账到{{{{PERSON|{n}}}}}的银行卡 {{{{BANK_CARD|{card}}}}}，谢谢。", f"收款银行卡号：{{{{BANK_CARD|{card}}}}}"]))
for _ in range(10):
    add("pii_zh", "zh", f"护照号码：{{{{PASSPORT|E{rnd(string.digits, 8)}}}}}，请在办理时携带。")

# ---- English PII -------------------------------------------------------------------------------
for _ in range(25):
    n, e = en_name(), email()
    add("pii_en", "en", R.choice([f"Please contact {{{{PERSON|{n}}}}} at {{{{EMAIL_ADDRESS|{e}}}}}.", f"Send the invoice to {{{{PERSON|{n}}}}} ({{{{EMAIL_ADDRESS|{e}}}}}) by Friday.", f"My name is {{{{PERSON|{n}}}}} and my email is {{{{EMAIL_ADDRESS|{e}}}}}."]))
for _ in range(15):
    n, p = en_name(), f"+1 {R.randint(201,989)}-{R.randint(200,999)}-{R.randint(1000,9999)}"
    add("pii_en", "en", R.choice([f"Call {{{{PERSON|{n}}}}} on {{{{PHONE_NUMBER|{p}}}}} tomorrow.", f"{{{{PERSON|{n}}}}}'s phone number is {{{{PHONE_NUMBER|{p}}}}}."]))
for _ in range(10):
    c = visa()
    add("pii_en", "en", R.choice([f"My credit card number is {{{{BANK_CARD|{c}}}}}, expires 12/29.", f"Charge card {{{{BANK_CARD|{c}}}}} for the order."]))
for _ in range(8):
    add("pii_en", "en", f"Her passport number is {{{{PASSPORT|X{rnd(string.digits, 7)}}}}} and it expires next year.")

# ---- mixed zh/en ---------------------------------------------------------------------------------
for _ in range(25):
    n, e, p = cn_name(), email(), phone()
    add("mixed", "mixed", R.choice([f"Hi {{{{PERSON|{n}}}}}, please send the contract to {{{{EMAIL_ADDRESS|{e}}}}} before Friday.", f"请联系 {{{{PERSON|{en_name()}}}}}，email: {{{{EMAIL_ADDRESS|{e}}}}}，手机 {{{{PHONE_NUMBER|{p}}}}}。", f"Customer {{{{PERSON|{n}}}}} 的电话是 {{{{PHONE_NUMBER|{p}}}}}，please call back."]))

# ---- API keys / tokens (synthetic) -----------------------------------------------------------------
KEYGEN = [("aws", lambda: aws_key(), 'aws_access_key_id = "{}"'), ("github", lambda: gh_token(), "GITHUB_TOKEN={}"), ("stripe", lambda: stripe_key(), "stripe.api_key = '{}'"), ("slack", lambda: slack_bot(), "SLACK_BOT_TOKEN={}"), ("openai", lambda: openai_key(), "OPENAI_API_KEY={}"), ("anthropic", lambda: anthropic_key(), "ANTHROPIC_API_KEY={}"), ("hf", lambda: hf_token(), "export HF_TOKEN={}"), ("google", lambda: google_key(), "key: {}")]
for _ in range(60):
    nm, g, tpl = R.choice(KEYGEN); k = g()
    pre = R.choice(["", "Here is my config:\n", "请帮我检查这段配置：\n", "```\n"]); post = R.choice(["", "\n", "\n```", "\n为什么报401？"])
    add("api_key", "mixed", pre + tpl.replace("{}", "{{SECRET|" + k + "}}") + post)
for _ in range(15):
    j = jwt(); add("api_key", "en", R.choice([f"Authorization: Bearer {{{{SECRET|{j}}}}}", f"token = \"{{{{SECRET|{j}}}}}\"", f"my jwt is {{{{SECRET|{j}}}}} can you decode it?"]))
for _ in range(10):
    add("api_key", "en", f"Use this key:\n{{{{SECRET|{pem()}}}}}\nand keep it safe.")
for _ in range(12):
    pw = pwd(); add("api_key", "mixed", R.choice([f"数据库密码是 {{{{SECRET|{pw}}}}}，不要外传", f"password = \"{{{{SECRET|{pw}}}}}\"", f"登录口令：{{{{SECRET|{pw}}}}}"]))

# ---- DB connection strings / internal addresses --------------------------------------------------------------------
for _ in range(25):
    u = R.choice(["mysql", "postgresql", "mongodb", "redis"]); host = R.choice([ip_int(), "db01.corp.example", "pg-master.internal"]); pw = dbpass()
    cs = f"{u}://app_user:{pw}@{host}:{R.choice([3306, 5432, 27017, 6379])}/orders"
    add("db_conn", "mixed", R.choice([f"连接串：{{{{DB_CONNECTION_STRING|{cs}}}}}", f"DATABASE_URL={{{{DB_CONNECTION_STRING|{cs}}}}}", f"spring.datasource.url={{{{DB_CONNECTION_STRING|{cs}}}}}"]))
for _ in range(25):
    ip = ip_int(); add("internal", "mixed", R.choice([f"服务部署在 {{{{IP_INTERNAL|{ip}}}}}，端口 8080。", f"ssh admin@{{{{IP_INTERNAL|{ip}}}}}", f"The staging server is at {{{{IP_INTERNAL|{ip}}}}}."]))
for _ in range(10):
    h = R.choice(["git", "jenkins", "nexus", "db-master", "vault"]) + "." + R.choice(["corp", "internal", "intranet"])
    add("internal", "mixed", f"请访问 http://{{{{INTERNAL_DOMAIN|{h}}}}}/dashboard 查看。")

# ---- code / JSON / Markdown ------------------------------------------------------------------------------
for _ in range(15):
    k = aws_key(); pw = dbpass()
    add("code", "en", f"def connect():\n    client = boto3.client('s3', aws_access_key_id='{{{{SECRET|{k}}}}}')\n    return client  # see {R.choice(['README','docs'])}")
for _ in range(10):
    add("code", "en", "for i in range(10):\n    print(i * 2)\n# compute hash\nh = hashlib.md5(b'abc').hexdigest()  # 900150983cd24fb0d6963f7d28e17f72")
for _ in range(12):
    n, p, e = cn_name(), phone(), email()
    add("json", "mixed", json.dumps({"user": {"name": "§N§", "phone": "§P§", "email": "§E§"}, "ok": True}, ensure_ascii=False).replace("§N§", "{{PERSON|" + n + "}}").replace("§P§", "{{PHONE_NUMBER|" + p + "}}").replace("§E§", "{{EMAIL_ADDRESS|" + e + "}}"))
for _ in range(8):
    k = openai_key(); add("json", "en", json.dumps({"model": "m", "api_key": "§K§", "stream": False}).replace("§K§", "{{SECRET|" + k + "}}"))
for _ in range(10):
    n, e = en_name(), email(); add("markdown", "en", f"## Contacts\n\n| Name | Email |\n|---|---|\n| {{{{PERSON|{n}}}}} | {{{{EMAIL_ADDRESS|{e}}}}} |\n\n> Please keep this table private.")
for _ in range(6):
    add("markdown", "zh", "# 周报\n\n- 完成需求评审\n- 修复三个缺陷\n- 下周计划：性能优化\n\n**备注**：无风险。")

# ---- company / project names ----------------------------------------------------------------------------------
for _ in range(15):
    c = R.choice(COMPANIES_CN); add("org", "zh", R.choice([f"我们和{{{{ORGANIZATION|{c}}}}}签订了合作协议。", f"他目前在{{{{ORGANIZATION|{c}}}}}担任高级工程师。"]))
for _ in range(10):
    c = R.choice(COMPANIES_EN); add("org", "en", R.choice([f"We signed a deal with {{{{ORGANIZATION|{c}}}}} last week.", f"{{{{ORGANIZATION|{c}}}}} announced a new product."]))
for _ in range(10):
    p = R.choice(PROJECTS); add("project", "mixed", R.choice([f"请评估{{{{PROJECT_NAME|{p}}}}}的风险。", f"The status of {{{{PROJECT_NAME|{p}}}}} is confidential."]))
for _ in range(6):
    add("project", "mixed", f"检查 {{{{PROJECT_NAME|{R.choice(SYSTEMS)}}}}} 的接口权限。")

# ---- long text -----------------------------------------------------------------------------------------------------------
FILL = "本次评审会议讨论了产品路线图、预算分配以及下个季度的招聘计划，各部门负责人依次汇报了进展情况，并就跨团队协作中的依赖关系进行了充分沟通。" 
for _ in range(10):
    n, p, e, k = cn_name(), phone(), email(), aws_key()
    parts = [FILL * R.randint(3, 8) for _ in range(3)]
    add("long", "zh", parts[0] + f"联系人{{{{PERSON|{n}}}}}，电话{{{{PHONE_NUMBER|{p}}}}}。" + parts[1] + f"邮箱{{{{EMAIL_ADDRESS|{e}}}}}，临时密钥 {{{{SECRET|{k}}}}}。" + parts[2])
for _ in range(5): add("long", "zh", FILL * R.randint(15, 30))

# ---- overlap / multi-entity ----------------------------------------------------------------------------------------
for _ in range(20):
    n, p, i, e, a = cn_name(), phone(), id_card(), email(), R.choice(CN_CITIES)
    addr = f"{a[0]}{a[1]}{a[2]}{R.randint(1,99)}号"
    add("multi", "zh", f"客户{{{{PERSON|{n}}}}}（身份证{{{{CN_ID_CARD|{i}}}}}，手机{{{{PHONE_NUMBER|{p}}}}}，邮箱{{{{EMAIL_ADDRESS|{e}}}}}）住在{{{{ADDRESS|{addr}}}}}。")

# ---- confusable numbers / wrong-format / pseudo keys (hard negatives) ---------------------------------------------
for _ in range(25): add("confusable", "zh", R.choice([f"订单编号 {rnd(string.digits, 18)} 已发货。", f"物流单号 {rnd(string.digits, 16)}，预计明天送达。", f"流水号 {rnd(string.digits, 11)} 请保留。", f"时间戳 {R.randint(1600000000000, 1800000000000)} 毫秒。", f"商品条码 {rnd(string.digits, 13)}。", f"第 {R.randint(100000, 999999)} 号文件已归档。"]))
for _ in range(20): add("wrong_id", "zh", R.choice([f"证件号 {bad_id_card()} 校验失败，请重新输入。", f"身份证号写错了：{bad_id_card()}", f"测试数据 {rnd(string.digits, 17)}X 不是有效证件。"]))
for _ in range(25): add("pseudo_key", "en", R.choice([f"commit {hex_hash(40)} merged into main.", f"md5: {hex_hash(32)}", f"uuid: {hex_hash(8)}-{hex_hash(4)}-{hex_hash(4)}-{hex_hash(4)}-{hex_hash(12)}", f"build id {rnd(AN, 24)} succeeded", "export API_KEY=YOUR_API_KEY_HERE", "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "AWS example from the docs: AKIAIOSFODNN7EXAMPLE", "password: ********", "token=<your-token>", "secret = ${SECRET_FROM_ENV}", f"sha256 {hex_hash(64)}"]))
for _ in range(15): add("three_han", "zh", R.choice(["我们明天去公园玩，顺便买点水果。", "请问哪里可以买到新鲜蔬菜？", "手机号码格式需要校验，邮箱必须唯一。", "客户资料已经整理完毕，请查收。", "王者荣耀今天更新了新赛季。", "张家界风景区门票价格调整。", "李白的诗歌风格豪放飘逸。"]))

# ---- formatted / split sensitive content ---------------------------------------------------------------------------------
for _ in range(15):
    p = phone(); fm = R.choice([f"{p[:3]} {p[3:7]} {p[7:]}", f"{p[:3]}-{p[3:7]}-{p[7:]}"])
    add("formatted", "zh", R.choice([f"电话：{{{{PHONE_NUMBER|{fm}}}}}。", f"请联系\n{{{{PHONE_NUMBER|{fm}}}}}\n谢谢"]))
for _ in range(10):
    i = id_card(); fm = f"{i[:6]} {i[6:14]} {i[14:]}"; add("formatted", "zh", f"身份证号：{{{{CN_ID_CARD|{fm}}}}}（空格分隔）")
for _ in range(10):
    k = aws_key(); add("formatted", "en", f"key,\n\"{{{{SECRET|{k}}}}}\",\n;")

with open(OUT, "w", encoding="utf-8") as f:
    for c in cases: f.write(json.dumps(c, ensure_ascii=False) + "\n")
from collections import Counter
print(len(cases), "cases;", sum(len(c["entities"]) for c in cases), "gold entities")
print(dict(Counter(c["category"] for c in cases)))
print(dict(Counter(e["type"] for c in cases for e in c["entities"])))
