//go:build js && wasm

// Command pqcsign-wasm exposes core/webbridge to JavaScript as the global
// object `pqcsign`. It is a deliberately thin syscall/js shim: all behaviour
// (and all tests) live in webbridge/webkeys, which are pure Go.
//
// Every function except version() returns a Promise. Long operations (Argon2id,
// ML-DSA signing, PDF parsing) run on the Go side and block the wasm thread, so
// the web client loads this module inside a Web Worker; the worker can be
// terminated to abort a hostile PDF (upstream security finding SF-1).
//
// Binary values cross the boundary as Uint8Array, everything else as string.
// Errors are rejected as JS Error objects; for PIN-envelope failures `error.code`
// is one of pin_too_short | wrong_pin | corrupt | unsupported.
package main

import (
	"errors"
	"fmt"
	"syscall/js"

	"example.internal/pqc-pdf-sign/core/webbridge"
)

func main() {
	api := map[string]any{
		"version": js.FuncOf(func(js.Value, []js.Value) any { return webbridge.Version }),

		"generateKey": promise(func(a []js.Value) (any, error) {
			key, err := webbridge.GenerateKey()
			if err != nil {
				return nil, err
			}
			out := toUint8Array(key)
			wipe(key)
			return out, nil
		}),

		"exportPublicKey": promise(func(a []js.Value) (any, error) {
			key, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			defer wipe(key)
			return webbridge.ExportPublicKeyPEM(key)
		}),

		"createCSR": promise(func(a []js.Value) (any, error) {
			key, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			defer wipe(key)
			req, err := stringArg(a, 1)
			if err != nil {
				return nil, err
			}
			return webbridge.CreateCSR(key, req)
		}),

		"certMatchesKey": promise(func(a []js.Value) (any, error) {
			key, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			defer wipe(key)
			cert, err := stringArg(a, 1)
			if err != nil {
				return nil, err
			}
			return webbridge.CertMatchesKey(key, []byte(cert))
		}),

		"signPDF": promise(func(a []js.Value) (any, error) {
			pdf, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			key, err := bytesArg(a, 1)
			if err != nil {
				return nil, err
			}
			defer wipe(key)
			chain, err := stringArg(a, 2)
			if err != nil {
				return nil, err
			}
			opts, err := optionalStringArg(a, 3)
			if err != nil {
				return nil, err
			}
			signed, result, err := webbridge.SignPDF(pdf, key, []byte(chain), opts)
			if err != nil {
				return nil, err
			}
			return map[string]any{"signedPdf": toUint8Array(signed), "result": result}, nil
		}),

		"verifyPDF": promise(func(a []js.Value) (any, error) {
			pdf, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			root, err := stringArg(a, 1)
			if err != nil {
				return nil, err
			}
			crl, err := optionalStringArg(a, 2)
			if err != nil {
				return nil, err
			}
			return webbridge.VerifyPDF(pdf, []byte(root), []byte(crl))
		}),

		"protectKey": promise(func(a []js.Value) (any, error) {
			key, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			defer wipe(key)
			pin, err := stringArg(a, 1)
			if err != nil {
				return nil, err
			}
			blob, err := webbridge.ProtectKey(key, pin)
			if err != nil {
				return nil, err
			}
			return toUint8Array(blob), nil
		}),

		"unprotectKey": promise(func(a []js.Value) (any, error) {
			blob, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			pin, err := stringArg(a, 1)
			if err != nil {
				return nil, err
			}
			key, err := webbridge.UnprotectKey(blob, pin)
			if err != nil {
				return nil, err
			}
			out := toUint8Array(key)
			wipe(key)
			return out, nil
		}),

		"changePIN": promise(func(a []js.Value) (any, error) {
			blob, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			oldPIN, err := stringArg(a, 1)
			if err != nil {
				return nil, err
			}
			newPIN, err := stringArg(a, 2)
			if err != nil {
				return nil, err
			}
			out, err := webbridge.ChangePIN(blob, oldPIN, newPIN)
			if err != nil {
				return nil, err
			}
			return toUint8Array(out), nil
		}),

		"sha512Hex": promise(func(a []js.Value) (any, error) {
			data, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			return webbridge.SHA512Hex(data), nil
		}),

		"certFingerprint": promise(func(a []js.Value) (any, error) {
			pem, err := stringArg(a, 0)
			if err != nil {
				return nil, err
			}
			return webbridge.CertFingerprint([]byte(pem))
		}),

		"checkDeviceCertificate": promise(func(a []js.Value) (any, error) {
			pem, err := stringArg(a, 0)
			if err != nil {
				return nil, err
			}
			return webbridge.CheckDeviceCertificate([]byte(pem))
		}),

		"listSignatures": promise(func(a []js.Value) (any, error) {
			pdf, err := bytesArg(a, 0)
			if err != nil {
				return nil, err
			}
			return webbridge.ListSignatures(pdf)
		}),
	}

	js.Global().Set("pqcsign", js.ValueOf(api))

	// Tell the loader the API is registered (main then blocks forever so the
	// exported js.Funcs stay callable).
	if ready := js.Global().Get("__pqcsignReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}

// promise adapts fn to a JS function returning a Promise. fn runs in its own
// goroutine and must not call back into JS synchronously in a way that waits
// on the event loop.
func promise(fn func(args []js.Value) (any, error)) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		executor := js.FuncOf(func(_ js.Value, pa []js.Value) any {
			resolve, reject := pa[0], pa[1]
			go func() {
				defer func() {
					if r := recover(); r != nil {
						reject.Invoke(jsError(fmt.Errorf("pqcsign: internal panic: %v", r)))
					}
				}()
				out, err := fn(args)
				if err != nil {
					reject.Invoke(jsError(err))
					return
				}
				resolve.Invoke(js.ValueOf(out))
			}()
			return nil
		})
		defer executor.Release()
		return js.Global().Get("Promise").New(executor)
	})
}

func jsError(err error) js.Value {
	e := js.Global().Get("Error").New(err.Error())
	if code := webbridge.PINError(err); code != "" {
		e.Set("code", code)
	}
	return e
}

func bytesArg(args []js.Value, i int) ([]byte, error) {
	if i >= len(args) || !args[i].InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, fmt.Errorf("pqcsign: argument %d must be a Uint8Array", i)
	}
	b := make([]byte, args[i].Get("length").Int())
	js.CopyBytesToGo(b, args[i])
	return b, nil
}

func stringArg(args []js.Value, i int) (string, error) {
	if i >= len(args) || args[i].Type() != js.TypeString {
		return "", fmt.Errorf("pqcsign: argument %d must be a string", i)
	}
	return args[i].String(), nil
}

// optionalStringArg treats a missing/null/undefined argument as "".
func optionalStringArg(args []js.Value, i int) (string, error) {
	if i >= len(args) || args[i].IsNull() || args[i].IsUndefined() {
		return "", nil
	}
	s, err := stringArg(args, i)
	if err != nil {
		return "", errors.New("pqcsign: optional argument must be a string, null or undefined")
	}
	return s, nil
}

func toUint8Array(b []byte) js.Value {
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	return u8
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
