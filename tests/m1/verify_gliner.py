"""M1: run both candidate GLiNER models on EN + ZH sentences (real inference, CPU), compare label sets.
Output: spans per sentence as (label, text-slice, score). Only synthetic data."""
import time, sys, os, json, torch
torch.set_num_threads(4)
from gliner import GLiNER
import gliner
print("gliner", gliner.__version__, "torch", torch.__version__)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "models")
EN_LABELS = ["person", "email", "phone number", "address", "organization", "credit card number", "passport number", "id card number", "company", "location"]
ZH_LABELS = ["人名", "电子邮箱", "手机号码", "地址", "公司名称", "银行卡号", "护照号码", "身份证号"]
CASES = [
    ("en", "Please contact Alice Johnson at alice@example.com or call +1 212 555 0198 about the Acme Corp invoice."),
    ("en", "My name is Robert Smith and I live at 221B Baker Street, London. My passport number is X1234567."),
    ("zh", "张三的手机号是13800138000，邮箱 zhangsan@example.com，住在北京市海淀区中关村大街1号。"),
    ("zh", "请帮李四分析客户资料，他在腾讯公司工作，联系电话是 010-62345678。"),
    ("zh", "收件人：王小明，地址：上海市浦东新区世纪大道100号，邮编200120。"),
    ("zh", "今天天气不错，我们去公园散步吧，晚上一起吃火锅。"),
    ("mix", "Hi 陈伟, please send the contract to 上海华为技术有限公司 before Friday, email: chenwei@example.org"),
]
for name in ["gliner_multi_pii-v1", "gliner_multi-v2.1"]:
    path = os.path.join(ROOT, name)
    t0 = time.time()
    model = GLiNER.from_pretrained(path, local_files_only=False)
    print(f"\n===== {name} load {time.time()-t0:.1f}s =====")
    for labels_name, labels in (("EN-labels", EN_LABELS), ("ZH-labels", ZH_LABELS)):
        print(f"-- {labels_name}")
        for lang, text in CASES:
            t = time.time()
            ents = model.predict_entities(text, labels, threshold=0.3)
            ms = (time.time() - t) * 1000
            ents.sort(key=lambda e: e["start"])
            print(f"[{lang}] {ms:6.0f} ms  " + " | ".join(f"{e['label']}:{text[e['start']:e['end']]}({e['score']:.2f})" for e in ents))
