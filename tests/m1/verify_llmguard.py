"""M1: execute LLM Guard's real anonymize / vault / deanonymize code paths (commit 168c103) with
Presidio RecognizerResult inputs. Demonstrates both the reusable behaviour and the security gaps
that our Rust Vault closes."""
import sys, types
# llm_guard.__init__ imports heavy optional deps lazily; import submodules directly
from presidio_analyzer import RecognizerResult
from llm_guard.vault import Vault
from llm_guard.input_scanners.anonymize import Anonymize
from llm_guard.output_scanners.deanonymize import Deanonymize, MatchingStrategy

prompt = "请帮张三分析客户资料，他的手机号是13800138000，张三的邮箱 zs@example.com。"
def span(s):
    i = prompt.index(s); return i, i + len(s)
ents = [RecognizerResult("PERSON", *span("张三"), 0.85),
        RecognizerResult("PHONE_NUMBER", *span("13800138000"), 0.9),
        RecognizerResult("EMAIL_ADDRESS", *span("zs@example.com"), 0.99)]
# second occurrence of the same person must reuse the same placeholder
j = prompt.index("张三", prompt.index("张三") + 2)
ents.append(RecognizerResult("PERSON", j, j + 2, 0.85))

ents = Anonymize._remove_conflicts_and_get_text_manipulation_data(Anonymize.__new__(Anonymize), ents)
vault = Vault()
out, mapping = Anonymize._anonymize(prompt, ents, vault, use_faker=False)
print("anonymized :", out)
for ph, val in mapping: vault.append((ph, val)) if not vault.placeholder_exists(ph) else None
print("vault size :", len(vault.get()), "(placeholders:", [p for p, _ in vault.get()], ")")

model_reply = "已为[REDACTED_PERSON_1]整理好资料，联系 [REDACTED_PHONE_NUMBER_1]。"
print("deanonymize EXACT :", Deanonymize(vault).scan(out, model_reply)[0])

print("\n--- security gaps observed in upstream (motivation for the Rust Vault) ---")
# 1. fuzzy mode restores things the model never emitted as placeholders
fz = Deanonymize(vault, matching_strategy=MatchingStrategy.FUZZY)
print("FUZZY on forged text  :", fz.scan("", "REDACTED_PERSON_9 and [REDACTED_PHONE_NUMBER_l]")[0])
# 2. chained replace: restored value that looks like another placeholder gets re-substituted
v2 = Vault([("[REDACTED_PERSON_1]", "see [REDACTED_PHONE_NUMBER_1]"), ("[REDACTED_PHONE_NUMBER_1]", "13800138000")])
print("chained replace       :", Deanonymize(v2).scan("", "hi [REDACTED_PERSON_1]")[0], "  <- value re-expanded")
# 3. no session / tenant scoping: any holder of the Vault object restores everything
print("vault has no tenant/session/TTL fields:", [a for a in dir(Vault) if not a.startswith('_')])
