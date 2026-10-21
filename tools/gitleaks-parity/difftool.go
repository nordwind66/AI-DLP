// difftool: run the REAL gitleaks detector (default config) over a list of samples and print findings.
// input : JSON array of strings on stdin;  output: JSON array (one entry per sample) of findings.
package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type out struct {
	Rule    string  `json:"rule"`
	Secret  string  `json:"secret"`
	Match   string  `json:"match"`
	Entropy float32 `json:"entropy"`
}

func main() {
	b, _ := io.ReadAll(os.Stdin)
	var samples []string
	if err := json.Unmarshal(b, &samples); err != nil {
		panic(err)
	}
	decode := 0
	if len(os.Args) > 1 && os.Args[1] == "decode" {
		decode = 5
	}
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		panic(err)
	}
	d.MaxDecodeDepth = decode
	res := make([][]out, len(samples))
	for i, s := range samples {
		fs := d.DetectString(s)
		res[i] = []out{}
		for _, f := range fs {
			res[i] = append(res[i], out{f.RuleID, f.Secret, f.Match, f.Entropy})
		}
	}
	json.NewEncoder(os.Stdout).Encode(res)
}
