module github.com/AyoubAchour/net-switch

go 1.27.3

require gvisor.dev/gvisor v0.0.0-20261017122056-1b7906fdee8c

replace gvisor.dev/gvisor => ./third_party/gvisor

require (
	github.com/quic-go/quic-go v0.64.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
