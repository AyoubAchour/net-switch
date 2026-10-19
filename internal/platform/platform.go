// Package platform defines OS operations independently of the control loop.
package platform

import (
	"context"
	"github.com/AyoubAchour/net-switch/internal/apps"
)

type TCPSelector struct {
	apps.Tuple
	ProcessStarted string `json:"processStarted,omitempty"`
}

// System executes OS operations; blocking reads are dispatched to workers.
// Results use the existing helper/API JSON vocabulary to retain the Node oracle
// boundary and avoid baking Windows handles into the controller.
type System interface {
	Call(context.Context, string, map[string]any) (any, error)
	Stream(context.Context, string, func([]byte), func(error))
}
