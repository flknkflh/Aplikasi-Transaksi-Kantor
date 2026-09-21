module example.internal/pqc-pdf-sign/tools/ca-admin

go 1.27.0

require (
	example.internal/pqc-pdf-sign/core v0.0.0
	golang.org/x/crypto v0.55.0
)

require (
	github.com/digitorus/pdf v0.2.0 // indirect
	github.com/digitorus/pdfsign v1.0.0-rc2 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20260821105541-05f79448fa77 // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	github.com/mattetti/filebuffer v1.0.1 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	golang.org/x/image v0.45.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace example.internal/pqc-pdf-sign/core => ../../core
