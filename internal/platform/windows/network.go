package winplatform

import (
	"errors"
	"fmt"
	"os"
	"time"
)

type networkAdapter struct {
	Alias           string   `json:"alias"`
	GUID            string   `json:"guid"`
	MAC             string   `json:"mac"`
	Index           uint32   `json:"index"`
	Description     string   `json:"description"`
	Status          string   `json:"status"`
	MediaType       string   `json:"mediaType"`
	LinkSpeed       string   `json:"linkSpeed"`
	Virtual         bool     `json:"virtual"`
	Gateway         *string  `json:"gateway"`
	RouteMetric     *uint32  `json:"routeMetric"`
	IPv4            *string  `json:"ipv4"`
	IPv4s           []string `json:"ipv4s"`
	Metric          *uint32  `json:"metric"`
	AutomaticMetric *bool    `json:"automaticMetric"`
	SSID            *string  `json:"ssid"`
}

type defaultRoute struct {
	Gateway          string `json:"gateway"`
	InterfaceAddress string `json:"interfaceAddress"`
	Metric           uint32 `json:"metric"`
}

type networkLine struct {
	ReadAt        int64            `json:"readAt"`
	Adapters      []networkAdapter `json:"adapters"`
	DefaultRoutes []defaultRoute   `json:"defaultRoutes"`
	Policy        any              `json:"policy"`
}

type networkReadError struct{ error }

func streamNetwork(changed <-chan struct{}, emit func() error, refresh, coalesce time.Duration) error {
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	var burst <-chan time.Time
	var timer *time.Timer
	var retry <-chan time.Time
	var retryTimer *time.Timer
	backoff := 500 * time.Millisecond
	read := func() error {
		err := emit()
		var failed *networkReadError
		if errors.As(err, &failed) {
			fmt.Fprintf(os.Stderr, "network read failed; retrying: %v\n", err)
			retryTimer = time.NewTimer(backoff)
			retry = retryTimer.C
			backoff = min(2*time.Second, backoff*2)
			return nil
		}
		backoff = 500 * time.Millisecond
		return err
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()
	if err := read(); err != nil {
		return err
	}
	for {
		select {
		case <-changed:
			// A fixed window coalesces a burst without starving updates when
			// Windows keeps sending notifications for a busy interface.
			if burst == nil && retry == nil {
				timer = time.NewTimer(coalesce)
				burst = timer.C
			}
			continue
		case <-burst:
			burst = nil
		case <-ticker.C:
		case <-retry:
			retry = nil
		}
		if retry != nil {
			continue
		}
		if err := read(); err != nil {
			// Only output failures end the stream. Read failures never publish
			// partial data and retry without waiting for a process restart.
			return err
		}
	}
}
