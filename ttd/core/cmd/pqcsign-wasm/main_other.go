//go:build !(js && wasm)

// Command pqcsign-wasm is the WebAssembly entry point (see main_js.go). On any
// other platform it only tells you how to build it, so `go build ./...` and
// `go vet ./...` stay green on developer machines.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "pqcsign-wasm only runs as WebAssembly: build with GOOS=js GOARCH=wasm (see web/build.sh)")
	os.Exit(2)
}
