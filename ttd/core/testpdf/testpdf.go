// Package testpdf embeds sample PDFs for core tests and the CLI's default
// spike input. The files are unmodified test fixtures from digitorus/pdfsign
// (BSD-2-Clause); see LICENSES/THIRD_PARTY_NOTICES.md. Kept out of a _test.go
// file so the spike CLI can reuse the same fixture as its default input.
package testpdf

import _ "embed"

//go:embed sample.pdf
var sample []byte

//go:embed sample-multipage.pdf
var sampleMultipage []byte

// Sample returns a small single-page PDF.
func Sample() []byte { return append([]byte(nil), sample...) }

// SampleMultipage returns a multi-page PDF.
func SampleMultipage() []byte { return append([]byte(nil), sampleMultipage...) }
