// Package rpcdb maps well-known pipe names to the MS-RPC protocols served on
// them. pipes.json is generated from https://github.com/jcspencer/rpc-interfaces
// (MIT License, see LICENSE).
package rpcdb

//go:generate go run gen.go

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/thesubtlety/pipescry/internal/model"
)

//go:embed pipes.json
var raw []byte

var byPipe = func() map[string][]model.RPCProtocol {
	m := map[string][]model.RPCProtocol{}
	if err := json.Unmarshal(raw, &m); err != nil {
		panic("rpcdb: " + err.Error())
	}
	return m
}()

// Lookup takes a normalized pipe name and returns its known protocols, or an
// empty slice. Callers must not modify the result.
func Lookup(name string) []model.RPCProtocol {
	if ps, ok := byPipe[strings.ToLower(name)]; ok {
		return ps
	}
	return []model.RPCProtocol{}
}
