"""Patch a *copy* of upstream gitleaks (never third_party itself) so that
  (1) utils.Validate dumps each rule's true/false-positive samples to $GL_CORPUS (JSONL), and
  (2) cmd/difftool (our in-process comparison driver) is added.
"""
import os, shutil, sys
work = sys.argv[1]
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
p = os.path.join(work, "cmd/generate/config/utils/validate.go")
s = open(p).read()
s = s.replace('import (\n\t"strings"', 'import (\n\t"encoding/json"\n\t"os"\n\t"strings"', 1)
s = s.replace('func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {\n\tr := &rule', '''func dumpCorpus(id string, tps, fps []string) {
	f := os.Getenv("GL_CORPUS")
	if f == "" {
		return
	}
	fh, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer fh.Close()
	b, _ := json.Marshal(map[string]any{"rule": id, "tps": tps, "fps": fps})
	fh.Write(append(b, '\\n'))
}

func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	dumpCorpus(rule.RuleID, truePositives, falsePositives)
	r := &rule''', 1)
open(p, "w").write(s)
os.makedirs(os.path.join(work, "cmd/difftool"), exist_ok=True)
shutil.copy(os.path.join(root, "tools/gitleaks-parity/difftool.go"), os.path.join(work, "cmd/difftool/main.go"))
