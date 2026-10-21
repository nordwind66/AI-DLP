"""Synthetic Chinese training data for GLiNER (PII-style NER), in GLiNER's format:
   {"tokenized_text": [tok, ...], "ner": [[start_tok, end_tok_inclusive, "label"], ...]}
Tokenization = services/nlp/dlp_nlp/splitter.py (one token per Han char) – the SAME splitter must be installed at
inference time (dlp_nlp.splitter.install). Labels are the English labels the engine uses.

Leakage control: this generator uses its own lexicons and sentence templates that are disjoint from
tests/data/accuracy/build_dataset.py; `--check-leak` verifies no training text equals an evaluation text and no
evaluation entity string (name/org/address) appears in training data.
Everything is synthetic; no real person, company or address is used.
"""
import argparse, json, os, random, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "services", "nlp"))
from dlp_nlp.splitter import CjkTokenSplitter

SUR = list("钱孔曹严华金魏陶姜戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳酆鲍史唐费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平黄穆萧尹")
GIV = ["嘉怡", "明轩", "雅琪", "俊杰", "思颖", "志强", "文博", "晓萱", "天佑", "诗涵", "建国", "梦瑶", "泽宇", "紫涵", "浩宇", "静怡", "春梅", "德华", "秋菊", "国栋", "海燕", "宏伟", "玉兰", "鹏", "磊", "婷", "凯", "琳", "彬", "颖"]
ORG_PRE = ["青云", "远航", "恒瑞", "鼎盛", "海川", "昆仑", "天工", "星辰", "博远", "金桥", "瑞丰", "长风", "云帆", "智联", "同方"]
ORG_SUF = ["科技有限公司", "信息技术有限公司", "网络股份有限公司", "咨询有限公司", "集团", "研究院", "银行股份有限公司", "医疗科技有限公司"]
PROV = [("江西省南昌市", "红谷滩区"), ("山东省济南市", "历下区"), ("福建省厦门市", "思明区"), ("河南省郑州市", "金水区"), ("辽宁省沈阳市", "和平区"), ("重庆市", "渝北区"), ("天津市", "南开区"), ("云南省昆明市", "盘龙区")]
STREET = ["解放路", "建设大道", "中山东路", "滨江大道", "青年街", "光华路", "学府路", "迎宾大道"]
PERSON_T = ["{p}是我们部门的新同事，请多关照。", "请把报告交给{p}，他会负责后续跟进。", "昨天{p}来公司面试了，表现不错。", "联系人：{p}，办公室在三楼。", "客户经理{p}已经回复了邮件。", "据{p}介绍，项目下周启动。", "麻烦通知{p}明天上午开会。", "{p}的工号已经录入系统。", "收件人{p}，请在周五前签收。", "我是{p}，想咨询一下退款流程。", "感谢{p}提供的资料，我们会尽快处理。", "{p}和{q}将共同负责这次活动。"]
ORG_T = ["我们已经与{o}签署了保密协议。", "{o}的招标文件需要在周三前提交。", "他曾在{o}担任技术总监。", "请核对{o}的开票信息。", "{o}将作为本次项目的供应商。"]
ADDR_T = ["快递请寄到{a}。", "公司注册地址为{a}。", "会议地点：{a}，请提前十分钟到达。", "发货地址是{a}，联系人电话稍后补充。"]
NEG_T = ["今天的天气非常适合出门散步。", "请把这份文档翻译成英文并保持原有格式。", "下个季度的预算需要重新评估。", "服务器在凌晨两点完成了例行维护。", "这个功能的测试用例已经全部通过。", "他们讨论了新产品的定价策略和推广渠道。", "手机号码和邮箱地址需要在注册时填写。", "公司地址与联系人信息请参考附件模板。"]


def tok(text):
    return [(t, s, e) for t, s, e in CjkTokenSplitter()(text)]


def make(text, spans):
    toks = tok(text)
    ner = []
    for (cs, ce, label) in spans:
        a = next((i for i, (_, s, e) in enumerate(toks) if s <= cs < e), None)
        b = next((i for i, (_, s, e) in enumerate(toks) if s < ce <= e), None)
        if a is not None and b is not None and b >= a:
            ner.append([a, b, label])
    return {"tokenized_text": [t for t, _, _ in toks], "ner": ner}


def fill(tpl, **vals):
    text, spans, out = tpl, [], ""
    # sequential replacement keeps offsets right
    import re
    pos = 0
    for m in re.finditer(r"\{(\w)\}", tpl):
        out += tpl[pos:m.start()]
        v, label = vals[m.group(1)]
        spans.append((len(out), len(out) + len(v), label))
        out += v
        pos = m.end()
    out += tpl[pos:]
    return out, spans


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=os.path.join(ROOT, "build/zh_train.json"))
    ap.add_argument("--check-leak", action="store_true")
    a = ap.parse_args()
    R = random.Random(a.seed)
    name = lambda: R.choice(SUR) + R.choice(GIV)
    data, texts = [], set()
    ev = [json.loads(l) for l in open(os.path.join(ROOT, "tests/data/accuracy/dataset.jsonl"), encoding="utf-8")]
    banned = {c["text"][e["start"]:e["end"]] for c in ev for e in c["entities"] if e["type"] in ("PERSON", "ORGANIZATION", "ADDRESS")}
    while len(data) < a.n:
        k = R.random()
        if k < 0.42:
            p, q = name(), name()
            t, sp = fill(R.choice(PERSON_T), p=(p, "person"), q=(q, "person"))
        elif k < 0.60:
            o = R.choice(ORG_PRE) + R.choice(ORG_SUF)
            t, sp = fill(R.choice(ORG_T), o=(o, "organization"))
        elif k < 0.78:
            pv, d = R.choice(PROV)
            addr = f"{pv}{d}{R.choice(STREET)}{R.randint(1, 399)}号"
            t, sp = fill(R.choice(ADDR_T), a=(addr, "address"))
        elif k < 0.90:
            p = name(); ph = "1" + R.choice("3578") + "".join(R.choice("0123456789") for _ in range(9))
            t, sp = fill("{p}的手机号是{n}，请及时联系。", p=(p, "person"), n=(ph, "phone number"))
        else:
            t, sp = R.choice(NEG_T), []
        if t in texts or any(b in t for b in banned):
            continue
        texts.add(t)
        data.append(make(t, sp))
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(data, open(a.out, "w"), ensure_ascii=False)
    print(len(data), "samples ->", a.out)
    if a.check_leak:
        ev = [json.loads(l) for l in open(os.path.join(ROOT, "tests/data/accuracy/dataset.jsonl"), encoding="utf-8")]
        ev_texts = {c["text"] for c in ev}
        ev_ents = {c["text"][e["start"]:e["end"]] for c in ev for e in c["entities"] if e["type"] in ("PERSON", "ORGANIZATION", "ADDRESS")}
        train_text = "\n".join(texts)
        same = texts & ev_texts
        leaked = [e for e in ev_ents if e in train_text]
        print("identical texts:", len(same), "| eval entity strings found in training text:", len(leaked), leaked[:5])
        assert not same, "training/eval text overlap"


if __name__ == "__main__":
    main()
