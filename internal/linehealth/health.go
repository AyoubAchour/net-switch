package linehealth

const (
	AddressMissesToFail        = 2
	RouteMissesToFail          = 2
	RouteStaleMS         int64 = 30000
	RouteReadEveryMS     int64 = 5000
	MinPollGapMS         int64 = 400
	ProbeFailsToFail           = 3
	ProbePassesToRecover       = 2
	PassWaitMS           int64 = 30000
)

type Route struct {
	Present bool  `json:"present"`
	At      int64 `json:"at"`
}
type Health struct {
	Up            *bool   `json:"up"`
	HadAddress    *bool   `json:"hadAddress"`
	AddressMisses int     `json:"addressMisses"`
	RouteMisses   int     `json:"routeMisses"`
	Route         *Route  `json:"route"`
	RecoveredAt   *int64  `json:"recoveredAt"`
	LastPollAt    *int64  `json:"lastPollAt"`
	ProbeFails    int     `json:"probeFails"`
	ProbePasses   int     `json:"probePasses"`
	Offline       bool    `json:"offline"`
	AwaitingPass  bool    `json:"awaitingPass"`
	LastAnswerAt  *int64  `json:"lastAnswerAt"`
	Reason        *string `json:"reason"`
}

func Bool(v bool) *bool { return &v }
func ptr[T any](v T) *T { return &v }
func value(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
func (h *Health) Reset() { *h = Health{} }
func (h *Health) ResetProbes() {
	h.ProbeFails = 0
	h.ProbePasses = 0
	h.Offline = false
	h.AwaitingPass = false
	h.LastAnswerAt = nil
}
func (h *Health) RestartKeeping(offline, awaiting bool, now int64) {
	h.Reset()
	h.Offline = offline
	if awaiting {
		h.AwaitingPass = true
		h.RecoveredAt = ptr(now)
	}
}
func (h *Health) InDoubt() bool { return h.ProbeFails > 0 || h.Offline || h.AwaitingPass }
func (h *Health) NoteProbe(ok *bool, now int64) {
	if ok == nil || (h.RecoveredAt != nil && now < *h.RecoveredAt) {
		return
	}
	h.LastAnswerAt = ptr(now)
	if *ok {
		h.ProbeFails = 0
		h.ProbePasses++
		h.AwaitingPass = false
		if h.Offline && h.ProbePasses >= ProbePassesToRecover {
			h.Offline = false
		}
	} else {
		h.ProbePasses = 0
		h.ProbeFails++
		if h.ProbeFails >= ProbeFailsToFail {
			h.Offline = true
		}
	}
}
func (h *Health) NoteRoute(present *bool, now int64) {
	if present == nil || (h.RecoveredAt != nil && now < *h.RecoveredAt) {
		return
	}
	if h.Route == nil || now-h.Route.At > RouteStaleMS {
		h.RouteMisses = 0
	}
	h.Route = &Route{*present, now}
	if *present {
		h.RouteMisses = 0
	} else {
		h.RouteMisses++
	}
}
func (h *Health) Check(address bool, now int64, tested bool) *bool {
	if h.LastPollAt != nil && now-*h.LastPollAt < MinPollGapMS {
		return h.Up
	}
	h.LastPollAt = ptr(now)
	if h.HadAddress != nil && !*h.HadAddress && address {
		h.Route = nil
		h.RouteMisses = 0
		h.ResetProbes()
		h.RecoveredAt = ptr(now)
		h.AwaitingPass = h.Up != nil && !*h.Up
	}
	h.HadAddress = Bool(address)
	if address {
		h.AddressMisses = 0
	} else {
		h.AddressMisses++
	}
	last := max(value(h.RecoveredAt), value(h.LastAnswerAt))
	if h.AwaitingPass && !h.Offline && now-last >= PassWaitMS {
		h.AwaitingPass = false
	}
	routeMissing := h.Route != nil && now-h.Route.At <= RouteStaleMS && !h.Route.Present
	clean := address && !routeMissing && !h.Offline && !(tested && h.AwaitingPass)
	why := "checking"
	if !address {
		why = "no address"
	} else if routeMissing {
		why = "no default route"
	} else if h.Offline {
		why = "no internet"
	}
	if h.Up == nil {
		h.Up = Bool(clean)
		if clean {
			h.Reason = nil
		} else {
			h.Reason = &why
		}
	} else if *h.Up {
		if h.AddressMisses >= AddressMissesToFail {
			h.Up = Bool(false)
			h.Reason = ptr("no address")
		} else if routeMissing && h.RouteMisses >= RouteMissesToFail {
			h.Up = Bool(false)
			h.Reason = ptr("no default route")
		} else if h.Offline {
			h.Up = Bool(false)
			h.Reason = ptr("no internet")
		}
	} else if clean {
		h.Up = Bool(true)
		h.Reason = nil
	} else {
		h.Reason = &why
	}
	return h.Up
}
