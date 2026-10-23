//go:build !lifecycle_test && !acceptance

package testproxy

import "context"

const Enabled = false

type Server struct{}

func New(context.Context, Options) (*Server, error) { return nil, ErrDisabled }
func (*Server) Close() error                        { return nil }
func (*Server) Status() Status                      { return Status{} }
