// The acceptance suites' QUIC fixture, in its own module so QUIC stays out of
// Net Switch's dependencies: the product's go.mod and vendor/ never see it.
module github.com/AyoubAchour/net-switch/tests/quicfixture

go 1.27.2

require github.com/quic-go/quic-go v0.64.0

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
