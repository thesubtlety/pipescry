//go:build ignore

// gen.go rebuilds pipes.json from the rpc-interfaces database.
// Run with: go generate ./internal/rpcdb
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

const source = "https://raw.githubusercontent.com/jcspencer/rpc-interfaces/main/database.json"

type protocol struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	resp, err := http.Get(source)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", source, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var db struct {
		Protocols map[string]struct {
			ID       string `json:"id"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			NamedPipes []struct {
				Path string `json:"path"`
			} `json:"named_pipes"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(body, &db); err != nil {
		return err
	}
	out := map[string][]protocol{}
	for _, p := range db.Protocols {
		for _, np := range p.NamedPipes {
			path := strings.ReplaceAll(np.Path, "/", `\`)
			name := strings.ToLower(path[strings.LastIndexByte(path, '\\')+1:])
			if name == "" {
				continue
			}
			out[name] = append(out[name], protocol{p.ID, p.Metadata.Name})
		}
	}
	for _, ps := range out {
		sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("pipes.json", append(b, '\n'), 0o644)
}
