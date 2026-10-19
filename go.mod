module github.com/AyoubAchour/net-switch

go 1.27.2

require gvisor.dev/gvisor v0.0.0-20261017122056-1b7906fdee8c

replace gvisor.dev/gvisor => ./third_party/gvisor

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.48.0
	golang.org/x/time v0.15.0 // indirect
)
