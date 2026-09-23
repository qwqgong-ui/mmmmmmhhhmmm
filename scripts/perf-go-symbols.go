//go:build ignore

// Recover function symbols from a stripped Go executable for an offline perf
// symfs. The original executable and running process are never modified.
package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run perf-go-symbols.go EXECUTABLE")
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	section := f.Section(".gopclntab")
	if section == nil {
		panic("missing .gopclntab")
	}
	pcln, err := section.Data()
	if err != nil {
		panic(err)
	}
	text := f.Section(".text")
	if text == nil {
		panic("missing .text")
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(pcln, text.Addr))
	if err != nil {
		panic(err)
	}
	for _, fn := range table.Funcs {
		// GNU binutils response-file quoting, not shell quoting.
		name := strings.ReplaceAll(strings.ReplaceAll(fn.Name, "\\", "\\\\"), "\"", "\\\"")
		fmt.Printf("--add-symbol \"%s=.text:0x%x,global,function\"\n", name, fn.Entry-text.Addr)
	}
}
