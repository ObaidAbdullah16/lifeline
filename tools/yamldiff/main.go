// Command yamldiff prints yamlite's parse of a YAML file as JSON (used by scripts/yaml-difftest.sh).
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ObaidAbdullah16/lifeline/internal/yamlite"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	v, err := yamlite.Parse(string(b))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR", err)
		os.Exit(2)
	}
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}
