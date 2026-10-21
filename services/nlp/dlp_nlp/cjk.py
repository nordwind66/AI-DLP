"""CJK helpers: language heuristic and Chinese person-name boundary refinement.

Why this exists (measured, see docs/m1_gliner_verify.txt): both GLiNER multi models return the span
"张三的手机号是13800138000" for PERSON, i.e. the name plus following context and the phone number,
and spaCy zh_core_web_sm tags "手机号" as PERSON. Refinement cuts such spans at function words /
digits, then checks the surname, instead of trusting raw model boundaries.
"""
import re

SURNAMES = set("王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾萧田董潘袁蔡蒋余于杜叶程魏苏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁冉骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉缪简车项连芦麦褚娄窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边卞姬师和仇栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩明佘池查麻苑迟邝")
COMPOUND = ["欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "尉迟", "公孙", "慕容", "长孙", "宇文", "司徒", "夏侯", "轩辕", "令狐", "端木", "独孤", "南宫", "西门", "百里", "呼延", "澹台", "公冶", "太史"]
# characters/words that terminate a name inside a model span
CUT_WORDS = ["的", "是", "在", "和", "与", "及", "跟", "给", "把", "被", "让", "请", "说", "想", "要", "会", "将", "为", "了", "也", "都", "就", "还", "又", "手机", "电话", "邮箱", "邮件", "地址", "住址", "身份证", "银行", "账号", "密码", "公司", "工作", "分析", "客户", "资料"]
TITLE_SUFFIX = ["先生", "女士", "小姐", "老师", "经理", "总监", "同志", "医生", "博士", "教授"]
_HAN = re.compile(r"[一-鿿]")
_STOP = re.compile(r"[0-9A-Za-z@:：，。；,.;!?！？()（）\[\]\s]")


def han_ratio(text: str) -> float:
    if not text:
        return 0.0
    n = len(_HAN.findall(text))
    return n / max(1, len(text))


def detect_langs(text: str):
    """Return the language codes Presidio's spaCy pipelines should run for this text."""
    letters = sum(1 for c in text if c.isalpha())
    han = len(_HAN.findall(text))
    latin = sum(1 for c in text if c.isascii() and c.isalpha())
    langs = []
    if han >= 2 and han / max(1, letters) >= 0.1:
        langs.append("zh")
    if latin >= 6 and (latin / max(1, letters) >= 0.25 or not langs):
        langs.append("en")
    return langs or ["en"]


def has_surname(name: str) -> bool:
    return bool(name) and (name[:2] in COMPOUND or name[0] in SURNAMES)


def refine_cjk_person(text: str, start: int, end: int, score: float):
    """Return (start, end, score, notes) for a PERSON span that contains Han characters, or None to drop it.
    Offsets are code-point offsets into ``text``."""
    span = text[start:end]
    if not _HAN.search(span):
        return start, end, score, {}
    notes = {}
    s = span.strip()
    lead = len(span) - len(span.lstrip())
    cut = len(s)
    m = _STOP.search(s)
    if m:
        cut = min(cut, m.start())
    for w in CUT_WORDS:
        i = s.find(w, 1)  # a name has at least one char before a cut word
        if 0 < i < cut:
            cut = i
    for t in TITLE_SUFFIX:
        i = s.find(t, 1)
        if 0 < i < cut:
            cut = i
    name = s[:cut]
    if cut != len(s):
        notes["refined"] = "cut"
        score *= 0.95
    if not (2 <= len(name) <= 4) and "·" not in name:
        return None
    if not all(_HAN.match(c) or c == "·" for c in name):
        return None
    if has_surname(name):
        notes["surname"] = "ok"
    else:
        # no known surname: keep only if the model is very sure; otherwise this is probably a common noun
        if score < 0.9:
            return None
        notes["surname"] = "unknown"
        score *= 0.8
    return start + lead, start + lead + len(name), min(score, 0.99), notes


# ----------------------------------------------------------------------------------------------
# Post-filters for NER output that is statistically plausible but structurally wrong. Found by the
# accuracy run (docs/ACCURACY_REPORT.md): identifiers such as SLACK_BOT_TOKEN, pronouns/common nouns
# ("Her", "Email", "everyone"), protocol acronyms tagged ORG ("TCP", "UDP") and place names that begin
# with a surname ("张家界").
# ----------------------------------------------------------------------------------------------
_LATIN_STOP = {
    "he", "she", "her", "his", "him", "they", "them", "their", "i", "me", "my", "we", "us", "our", "you", "your", "it", "its",
    "everyone", "everybody", "someone", "anyone", "nobody", "customer", "client", "user", "users", "team", "name", "email", "mail",
    "phone", "address", "password", "token", "key", "admin", "support", "sales", "manager", "hello", "hi", "dear", "thanks", "sir", "madam",
    "mr", "mrs", "ms", "dr", "the", "a", "an", "contact", "invoice", "contract", "company", "staff", "guest", "member", "friend",
}
_PLACE_SUFFIX = tuple("景区市县山湖路街村镇岛江河海园馆")
# common place names that start with a surname character
_PLACE_NAMES = {"张家界", "张家口", "张掖", "王府井", "朱家角", "杨浦", "林芝", "周庄", "石家庄", "苏州", "徐州", "金华", "马鞍山", "黄山", "黄河", "吴江", "章丘", "韩城", "白山", "唐山", "许昌", "孙吴", "高碑店", "汪清"}
_ORG_SUFFIX = re.compile(r"(?i)\b(inc|corp|corporation|ltd|llc|gmbh|co|company|group|limited|plc|bank|university|institute|technologies|systems)\b\.?$|(?:公司|集团|银行|大学|学院|研究院|研究所|中心|协会|基金会|医院|厂|局|部|委员会|事务所)$")


def refine_latin_person(text: str, start: int, end: int, score: float):
    """Drop identifiers, pronouns, lowercase words; return (start, end, score, notes) or None."""
    span = text[start:end].strip()
    if not span or _HAN.search(span):
        return start, end, score, {}
    if any(c in span for c in "_=:/\\@`#0123456789<>[]{}"):
        return None
    words = span.split()
    if not words or len(words) > 4:
        return None
    if any(w.lower().strip(".,;") in _LATIN_STOP for w in words) and len(words) == 1:
        return None
    if not all(w[0].isupper() for w in words if w[0].isalpha()):
        return None  # personal names are capitalised
    if len(words) == 1:
        # a single capitalised token is weak evidence: keep only if the model is confident
        if score < 0.9 or len(span) < 3 or span.isupper():
            return None
    return start, end, score, {}


def refine_org(text: str, start: int, end: int, score: float):
    span = text[start:end].strip()
    if not span:
        return None
    if any(c in span for c in "_=:/\\@`<>[]{}"):
        return None
    if _HAN.search(span):
        # sentence fragments ("公司地址是", "服务部署在") are not organization names
        if any(w in span for w in CUT_WORDS if w not in ("公司", "银行")) :
            return None
        return (start, end, score, {}) if (_ORG_SUFFIX.search(span) or 2 <= len(span) <= 8) else None
    # protocol / technology acronyms ("TCP", "UDP", "API", "JSON") are not organizations
    if span.isupper() and len(span) <= 5 and not _ORG_SUFFIX.search(span):
        return None
    if span.islower() or len(span) < 3:
        return None
    return start, end, score, {}


def is_place_like(text: str, end: int, name: str = "") -> bool:
    if name in _PLACE_NAMES:
        return True
    return end < len(text) and text[end] in _PLACE_SUFFIX


def refine_phone(text: str, start: int, end: int, score: float):
    """Presidio's phone recognizer accepts any digit run that is a *possible* number (timestamps,
    barcodes). Keep only spans that look written as a phone number: '+' prefix or digit-group separators."""
    span = text[start:end]
    digits = sum(c.isdigit() for c in span)
    if digits < 7 or digits > 15:
        return None
    if span.startswith("+") or any(c in span for c in " -()."):
        return start, end, score, {}
    return None


def refine_entity(etype, text, s, e, score):
    """Single entry point used by both backends. Returns (start, end, score, notes) or None to drop."""
    if etype == "PERSON":
        r = refine_cjk_person(text, s, e, score)
        if r is None:
            return None
        if _HAN.search(text[s:e]):
            return None if is_place_like(text, r[1], text[r[0]:r[1]]) else r
        return refine_latin_person(text, r[0], r[1], r[2])
    if etype == "ORGANIZATION":
        return refine_org(text, s, e, score)
    if etype == "PHONE_NUMBER":
        return refine_phone(text, s, e, score)
    if etype == "EMAIL_ADDRESS":
        return (s, e, score, {}) if "@" in text[s:e] else None
    if etype in ("CREDIT_CARD", "BANK_ACCOUNT", "NATIONAL_ID", "PASSPORT", "DRIVER_LICENSE", "IBAN", "MEDICAL_LICENSE"):
        span = text[s:e]
        return (s, e, score, {}) if sum(c.isdigit() for c in span) >= 5 else None
    return s, e, score, {}
