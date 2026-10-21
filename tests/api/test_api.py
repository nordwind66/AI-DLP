"""HTTP API tests against a running dlp-server (see scripts/linux/run_api_tests.sh).
Env: DLP_URL (default http://127.0.0.1:8080), DLP_KEY_USER, DLP_KEY_ADMIN (or files build/run/*.key).
Tests that need the NLP detectors are skipped (and reported as skipped, not passed) when /health says degraded."""
import json, os, unittest, urllib.request, urllib.error

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
URL = os.environ.get("DLP_URL", "http://127.0.0.1:8080")
def _key(env, f):
    return os.environ.get(env) or open(os.path.join(ROOT, "build/run", f)).read().strip()
USER, ADMIN = _key("DLP_KEY_USER", "user.key"), _key("DLP_KEY_ADMIN", "admin.key")
AWS = "AKIAZ3XQKVN5TLWM7EPD"   # synthetic
ID = "11010119900307002X"      # synthetic, valid checksum


def call(method, path, body=None, key=USER, raw=False, headers=None, ctype="application/json"):
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    h = {"Content-Type": ctype, **(headers or {})}
    if key:
        h["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(URL + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            b = r.read()
            return r.status, (b if raw else json.loads(b)), r.headers
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b), e.headers
        except Exception:
            return e.code, b, e.headers


def nlp_ready():
    try:
        s, b, _ = call("GET", "/v1/capabilities")
        return s == 200 and bool(b.get("full_capability"))
    except Exception:
        return False


class Auth(unittest.TestCase):
    def test_health_is_open_everything_else_needs_a_key(self):
        self.assertEqual(call("GET", "/health", key=None)[0], 200)
        for m, p in [("POST", "/v1/detect"), ("GET", "/v1/capabilities"), ("GET", "/metrics"), ("POST", "/v1/rules/reload")]:
            self.assertEqual(call(m, p, {"text": "x"}, key=None)[0], 401, p)
        self.assertEqual(call("POST", "/v1/detect", {"text": "x"}, key="wrong")[0], 401)

    def test_tenant_comes_from_the_key_not_the_body(self):
        s, b, _ = call("POST", "/v1/detect", {"text": "x", "tenant_id": "someone-else"})
        self.assertEqual((s, b["error"]["code"]), (403, "tenant_mismatch"))
        self.assertEqual(call("POST", "/v1/detect", {"text": "x", "tenant_id": "acme"})[0], 200)

    def test_admin_endpoints_need_scope(self):
        self.assertEqual(call("POST", "/v1/rules/reload")[0], 403)
        self.assertEqual(call("GET", "/metrics")[0], 403)
        self.assertEqual(call("POST", "/v1/rules/reload", key=ADMIN)[0], 200)
        self.assertEqual(call("GET", "/metrics", key=ADMIN, raw=True)[0], 200)


class Detection(unittest.TestCase):
    def test_scenario_a_phone(self):
        s, b, _ = call("POST", "/v1/sanitize", {"text": "张三的手机号是13800138000。"})
        self.assertEqual(s, 200)
        self.assertIn("138****8000", b["sanitized_text"])
        ph = [e for e in b["entities"] if e["entity_type"] == "PHONE_NUMBER"][0]
        self.assertEqual((ph["start"], ph["end"]), (7, 18))
        self.assertNotIn("value", ph)                       # never returns the value by default
        self.assertNotIn("13800138000", json.dumps(b["entities"]))   # nor in contexts
        for k in ("detector_status", "processing_time_ms", "actions", "policy_id", "decision"):
            self.assertIn(k, b)

    def test_scenario_c_credential_redacted_not_refused(self):
        s, b, _ = call("POST", "/v1/sanitize", {"text": f"aws_access_key_id = {AWS}"})
        self.assertEqual(b["decision"], "modified")
        self.assertNotIn(AWS, b["sanitized_text"])
        self.assertIn("[REDACTED_", b["sanitized_text"])

    def test_private_key_desensitized_and_block_is_opt_in(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 3 + "-----END RSA PRIVATE KEY-----"
        s, b, _ = call("POST", "/v1/sanitize", {"text": "k:\n" + pem})
        self.assertEqual(b["sanitized_text"], "k:\n[REDACTED_PRIVATE_KEY]")
        s, b, _ = call("POST", "/v1/sanitize", {"text": "k:\n" + pem, "policy_id": "block-secrets"})
        self.assertEqual((b["decision"], b["sanitized_text"]), ("blocked", None))
        s, b, _ = call("POST", "/v1/sanitize", {"text": "k:\n" + pem, "actions": {"PRIVATE_KEY": "BLOCK"}})
        self.assertEqual(b["decision"], "blocked")

    def test_id_card_validation_and_reveal_requires_scope(self):
        s, b, _ = call("POST", "/v1/detect", {"text": f"身份证 {ID} 与 110101199003070027"})
        self.assertEqual([e["entity_type"] for e in b["entities"]], ["CN_ID_CARD"])
        self.assertEqual(call("POST", "/v1/detect", {"text": "x", "reveal_values": True})[0], 403)
        s, b, _ = call("POST", "/v1/detect", {"text": f"身份证 {ID}", "reveal_values": True}, key=ADMIN)
        self.assertEqual(b["entities"][0]["value"], ID)

    def test_modes_directions_entities_filter(self):
        t = "mail a@example.com tel 13800138000"
        s, b, _ = call("POST", "/v1/detect", {"text": t, "entities": ["EMAIL_ADDRESS"]})
        self.assertEqual([e["entity_type"] for e in b["entities"]], ["EMAIL_ADDRESS"])
        self.assertIsNone(b["sanitized_text"])
        s, b, _ = call("POST", "/v1/detect", {"text": t, "mode": "sanitize", "direction": "response", "policy_id": "reversible"})
        self.assertIn("138****8000", b["sanitized_text"])        # response direction: mask, not anonymize
        self.assertEqual(call("POST", "/v1/detect", {"text": t, "direction": "sideways"})[0], 400)
        self.assertEqual(call("POST", "/v1/detect", {"text": t, "policy_id": "nope"})[0], 404)

    def test_errors_do_not_echo_text(self):
        secret = "SUPER-SECRET-TEXT-" + "z" * 20
        s, b, _ = call("POST", "/v1/detect", {"text": secret, "mode": "bogus"})
        self.assertEqual(s, 400)
        self.assertNotIn(secret, json.dumps(b))
        s, b, _ = call("POST", "/v1/detect", b'{"text": "' + secret.encode() + b'" broken', raw=False)
        self.assertEqual(s, 400)
        self.assertNotIn(secret, json.dumps(b))

    def test_limits(self):
        s, b, _ = call("POST", "/v1/detect", {"text": "a" * (5 << 20)})
        self.assertEqual(s, 413)
        s, b, _ = call("POST", "/v1/detect/batch", {"items": [{"text": "x"}] * 65})
        self.assertEqual(s, 413)

    def test_batch(self):
        s, b, _ = call("POST", "/v1/detect/batch", {"items": [{"text": "13800138000"}, {"text": "hello"}, {"text": "x", "policy_id": "nope"}], "mode": "sanitize"})
        r = b["results"]
        self.assertTrue(r[0]["ok"] and r[1]["ok"] and not r[2]["ok"])
        self.assertEqual(r[0]["result"]["sanitized_text"], "138****8000")
        self.assertEqual(r[2]["error"]["code"], "not_found")

    def test_payload_openai_and_anthropic(self):
        body = {"model": "m", "messages": [{"role": "user", "content": "tel 13800138000"}, {"role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{\"mail\":\"a@example.com\"}"}}]}]}
        s, b, _ = call("POST", "/v1/sanitize", {"payload": body})
        out = b["body"]
        self.assertEqual(b["protocol"], "openai.chat.completions")
        self.assertEqual(out["messages"][0]["content"], "tel 138****8000")
        self.assertEqual(out["messages"][1]["tool_calls"][0]["id"], "call_1")
        self.assertEqual(out["model"], "m")
        s, b, _ = call("POST", "/v1/sanitize", {"payload": {"id": "m1", "type": "message", "role": "assistant", "stop_reason": "end_turn", "content": [{"type": "thinking", "thinking": "phone 13800138000", "signature": "abc"}, {"type": "text", "text": "ok 13800138000"}]}, "direction": "response"})
        self.assertEqual(b["protocol"], "anthropic.messages")
        self.assertEqual([c["type"] for c in b["body"]["content"]], ["text"])    # signed block removed, text desensitized
        self.assertEqual(b["body"]["content"][0]["text"], "ok 138****8000")


class Vault(unittest.TestCase):
    def test_scenario_d_roundtrip_and_attacks(self):
        t = "请给张三发送一封邮件，邮箱是zhangsan@example.com。联系人：李四"
        s, b, _ = call("POST", "/v1/anonymize", {"text": t, "policy_id": "reversible", "session_id": "api-test-1"})
        sent = b["sanitized_text"]
        self.assertIn("[EMAIL_ADDRESS_1]", sent)
        self.assertNotIn("zhangsan@example.com", sent)
        reply = "已发送到[EMAIL_ADDRESS_1]，称呼[PERSON_1]，不存在[EMAIL_ADDRESS_9]。"
        s, r, _ = call("POST", "/v1/deanonymize", {"session_id": "api-test-1", "text": reply, "policy_id": "reversible"})
        self.assertEqual(s, 200)
        self.assertIn("zhangsan@example.com", r["text"])
        self.assertEqual(r["unknown_placeholders"], 1)
        self.assertIn("[EMAIL_ADDRESS_9]", r["text"])
        # another session / unknown session
        self.assertEqual(call("POST", "/v1/deanonymize", {"session_id": "api-test-2", "text": reply})[0], 404)
        # tenant mismatch in body
        self.assertEqual(call("POST", "/v1/deanonymize", {"session_id": "api-test-1", "text": reply, "tenant_id": "other"})[0], 403)
        # restoring into tool inputs is refused
        self.assertEqual(call("POST", "/v1/deanonymize", {"session_id": "api-test-1", "text": reply, "direction": "tool_input"})[0], 403)
        # skipping the response check needs a special scope
        self.assertEqual(call("POST", "/v1/deanonymize", {"session_id": "api-test-1", "text": reply, "check_response": False})[0], 403)
        # a leak inside the model reply is desensitized BEFORE restoration
        s, r, _ = call("POST", "/v1/deanonymize", {"session_id": "api-test-1", "text": f"[PERSON_1] 的密钥 {AWS} 和 [EMAIL_ADDRESS_1]"})
        self.assertNotIn(AWS, r["text"])
        self.assertIn("zhangsan@example.com", r["text"])

    def test_generated_session_id_is_unguessable(self):
        s, b, _ = call("POST", "/v1/anonymize", {"text": "联系人：王小明", "policy_id": "reversible"})
        sid = b["session_id"]
        self.assertGreaterEqual(len(sid), 32)
        s, r, _ = call("POST", "/v1/deanonymize", {"session_id": sid, "text": "[PERSON_1]"})
        self.assertEqual(r["text"], "王小明")


class Streaming(unittest.TestCase):
    @staticmethod
    def chunk(t):
        return "data: " + json.dumps({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": t}, "finish_reason": None}]}) + "\n\n"
    FIN = "data: " + json.dumps({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}) + "\n\ndata: [DONE]\n\n"

    def test_scenario_f_whole_stream(self):
        body = (self.chunk("call 138") + self.chunk("0013") + self.chunk("8000 now") + self.FIN).encode()
        s, out, h = call("POST", "/v1/scan/stream?policy_id=default", body, raw=True, ctype="text/event-stream")
        txt = out.decode()
        self.assertEqual(h["x-dlp-blocked"], "0")
        self.assertNotIn("13800138000", txt)
        self.assertIn("138****8000", txt)
        self.assertIn("[DONE]", txt)

    def test_scenario_f_incremental_nothing_early(self):
        sid = "api-stream-1"
        released = ""
        for part in ("call 138", "0013", "8000 now"):
            s, b, _ = call("POST", "/v1/scan/stream", {"stream_id": sid, "chunk": self.chunk(part), "policy_id": "default"})
            released += b["output"]
        self.assertEqual(released, "", "strict mode must not release anything before the terminal event")
        s, b, _ = call("POST", "/v1/scan/stream", {"stream_id": sid, "chunk": self.FIN, "final": True})
        self.assertIn("138****8000", b["output"])
        self.assertNotIn("13800138000", b["output"])
        self.assertTrue(b["finished"])

    def test_cross_chunk_secret(self):
        k = AWS
        body = (self.chunk("key " + k[:9]) + self.chunk(k[9:] + " end") + self.FIN).encode()
        s, out, _ = call("POST", "/v1/scan/stream", body, raw=True, ctype="text/event-stream")
        self.assertNotIn(k[:9], out.decode())
        self.assertIn("[REDACTED_", out.decode())


class Rules(unittest.TestCase):
    def test_reload_and_versions(self):
        s, b, _ = call("GET", "/v1/rules/versions", key=ADMIN)
        self.assertEqual(s, 200)
        self.assertTrue(any(v["active"] for v in b["versions"]))
        s, b, _ = call("POST", "/v1/rules/reload", key=ADMIN)
        self.assertEqual(s, 200)
        self.assertIn("fingerprint", b)

    def test_capabilities_and_openapi(self):
        s, b, _ = call("GET", "/v1/capabilities")
        self.assertEqual(s, 200)
        self.assertIn("detectors", b)
        self.assertIn("streaming", b)
        self.assertIn("default", b["policies"])
        s, y, _ = call("GET", "/openapi.yaml", key=None, raw=True)
        self.assertEqual(s, 200)
        self.assertIn(b"openapi: 3.0.3", y)


@unittest.skipUnless(nlp_ready(), "NLP service not ready: Presidio/GLiNER tests skipped (reported as skipped)")
class NlpIntegrated(unittest.TestCase):
    def test_scenario_b_english_name_from_ner(self):
        s, b, _ = call("POST", "/v1/sanitize", {"text": "Please contact Alice at alice@example.com."})
        types = {e["entity_type"]: e for e in b["entities"]}
        self.assertIn("EMAIL_ADDRESS", types)
        self.assertIn("PERSON", types, "name must come from NER")
        self.assertIn(types["PERSON"]["detector"], ("gliner", "presidio"))
        self.assertFalse(b["degraded"])
        ran = {d["name"] for d in b["detector_status"] if d["ran"]}
        self.assertTrue({"gliner", "presidio"} <= ran)

    def test_chinese_name_boundary_is_refined(self):
        s, b, _ = call("POST", "/v1/detect", {"text": "张三的手机号是13800138000。"})
        p = [e for e in b["entities"] if e["entity_type"] == "PERSON"]
        self.assertTrue(p and (p[0]["start"], p[0]["end"]) == (0, 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
