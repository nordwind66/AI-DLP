#!/usr/bin/env python3
"""Calling the DLP server over HTTP (stdlib only).
  DLP_URL=http://127.0.0.1:8080 DLP_KEY=<api key> python examples/python/http_client.py
"""
import json, os, urllib.request

URL = os.environ.get("DLP_URL", "http://127.0.0.1:8080")
KEY = os.environ["DLP_KEY"]


def post(path, body):
    req = urllib.request.Request(URL + path, data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


# 1. desensitize a prompt before it goes to the model
r = post("/v1/sanitize", {"text": "张三的手机号是13800138000。", "direction": "request"})
print("sanitized:", r["sanitized_text"], "| decision:", r["decision"], "| degraded:", r["degraded"])
for e in r["entities"]:
    print(f"  {e['entity_type']:14} [{e['start']},{e['end']}) {e['detector']:9} {e['action']}")

# 2. reversible anonymization round trip
a = post("/v1/anonymize", {"text": "请给张三发送邮件，邮箱是zhangsan@example.com。", "policy_id": "reversible", "session_id": "demo-session-1"})
print("to model :", a["sanitized_text"])
model_reply = "已向[EMAIL_ADDRESS_1]发送邮件，称呼[PERSON_1]。"      # what the LLM answered
d = post("/v1/deanonymize", {"session_id": "demo-session-1", "text": model_reply, "policy_id": "reversible"})
print("restored :", d["text"], "| unknown placeholders:", d["unknown_placeholders"])

# 3. a whole chat payload: only text fields change, ids / roles / model are untouched
p = post("/v1/sanitize", {"payload": {"model": "m", "messages": [{"role": "user", "content": "我的邮箱 a.b@example.com"}]}})
print("payload  :", json.dumps(p["body"], ensure_ascii=False))
