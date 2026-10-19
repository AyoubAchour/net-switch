package winplatform

type adapterReading struct {
	Alias string `json:"alias"`
	RX    uint64 `json:"rx"`
	TX    uint64 `json:"tx"`
}

type metersLine struct {
	Adapters []adapterReading `json:"adapters"`
}
