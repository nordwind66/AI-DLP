"""Download model weights into ./models (online, one-off). Runtime is fully offline afterwards.

Revisions are pinned (commit SHAs of the HF repos) so builds are reproducible.
"""
import os, sys, json
from huggingface_hub import snapshot_download

MODELS = {
    "gliner_multi_pii-v1": ("urchade/gliner_multi_pii-v1", "1fcf13e85f4eef5394e1fcd406cf2ca9ea82351d"),
    "gliner_multi-v2.1": ("urchade/gliner_multi-v2.1", "443d26d654e0324125a96bebd8e796c14ff2efe6"),
}
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
for local, (repo, rev) in MODELS.items():
    if len(sys.argv) > 1 and local not in sys.argv[1:]:
        continue
    dst = os.path.join(root, local)
    p = snapshot_download(repo_id=repo, revision=rev, local_dir=dst)
    print("downloaded", repo, "->", p, flush=True)

# Tokenizer/config of the GLiNER backbone (MIT). Only small files -> HF cache inside ./models/hf_home/hub
# so that the runtime can run with HF_HOME=./models/hf_home HF_HUB_OFFLINE=1.
cache = os.path.join(root, "hf_home", "hub")
snapshot_download(repo_id="microsoft/mdeberta-v3-base", revision="a0484667b22365f84929a935b5e50a51f71f159d",
                  allow_patterns=["config.json", "spm.model", "tokenizer_config.json"], cache_dir=cache)
print("downloaded backbone tokenizer files into", cache)
# offline resolution of "main" needs refs/main -> pinned sha
_refs = os.path.join(cache, "models--microsoft--mdeberta-v3-base", "refs")
os.makedirs(_refs, exist_ok=True)
open(os.path.join(_refs, "main"), "w").write("a0484667b22365f84929a935b5e50a51f71f159d")


# ---- supply-chain hardening: no pickle at runtime ---------------------------------------------------------------
# pytorch_model.bin is a pickle (loading an untrusted one can execute code). Revisions are pinned by SHA; in
# addition we convert once to safetensors using torch.load(weights_only=True) (tensors only) and the runtime
# loads model.safetensors, which GLiNER prefers over pytorch_model.bin. Hashes are printed for the manifest.
import hashlib
def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
try:
    import torch
    from safetensors.torch import save_file
    for local in MODELS:
        d = os.path.join(root, local)
        binp, stp = os.path.join(d, "pytorch_model.bin"), os.path.join(d, "model.safetensors")
        if os.path.exists(binp):
            print("sha256", local, "pytorch_model.bin", _sha(binp))
        if os.path.exists(binp) and not os.path.exists(stp):
            sd = torch.load(binp, map_location="cpu", weights_only=True)
            sd = {k: v.contiguous() for k, v in sd.items()}
            # tied/shared tensors are not allowed by safetensors: clone duplicates
            seen = {}
            for k, v in list(sd.items()):
                key = v.data_ptr()
                if key in seen:
                    sd[k] = v.clone()
                seen[key] = k
            save_file(sd, stp, metadata={"format": "pt", "converted_from": "pytorch_model.bin"})
            print("converted", local, "-> model.safetensors")
        if os.path.exists(stp):
            print("sha256", local, "model.safetensors", _sha(stp))
except Exception as e:  # conversion is hardening, not a requirement
    print("safetensors conversion skipped:", type(e).__name__, e)
