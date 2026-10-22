//go:build windows

package wintun

import (
	"errors"
	"fmt"
	"math"
)

type performanceSample struct {
	Status string   `json:"status"`
	Value  *float64 `json:"value"` // JSON null means absent, never zero throughput
	Error  string   `json:"error,omitempty"`
	Pair   int      `json:"pair"`
	Mode   string   `json:"mode"`
	Metric string   `json:"metric"`
	cause  error
}

func (s *performanceSample) finish(value float64, err error) {
	if err == nil && (value <= 0 || math.IsNaN(value) || math.IsInf(value, 0)) {
		err = fmt.Errorf("unusable measured value %g", value)
	}
	s.Status, s.Value, s.Error, s.cause = "valid", &value, "", nil
	if err != nil {
		s.Status, s.Value, s.Error, s.cause = "invalid", nil, err.Error(), err
	}
}

func newPerformanceSamples(pairs int, mode, metric string) []performanceSample {
	samples := make([]performanceSample, pairs)
	for i := range samples {
		samples[i] = performanceSample{Status: "invalid", Error: "sample not executed", Pair: i, Mode: mode, Metric: metric}
	}
	return samples
}

func pairedSampleRatios(ours, dll []performanceSample, reference ...string) ([]float64, error) {
	mode := "dll"
	if len(reference) != 0 {
		mode = reference[0]
	}
	if len(ours) == 0 || len(ours) != len(dll) {
		return nil, fmt.Errorf("integrity-invalid comparison: incomplete matched pairs ours=%d DLL=%d", len(ours), len(dll))
	}
	var invalid error
	for i := range ours {
		for _, side := range []struct {
			samples []performanceSample
			mode    string
		}{{ours, "ours"}, {dll, mode}} {
			s := side.samples[i]
			if s.Status != "valid" || s.Value == nil || s.Error != "" || s.Pair != i || s.Mode != side.mode || s.Metric != ours[0].Metric {
				cause := s.cause
				if cause == nil {
					cause = fmt.Errorf("%s (status=%s, pair=%d, mode=%s, metric=%s)", s.Error, s.Status, s.Pair, s.Mode, s.Metric)
				}
				invalid = errors.Join(invalid, fmt.Errorf("pair=%d mode=%s metric=%s: %w", i, side.mode, s.Metric, cause))
			}
		}
	}
	if invalid != nil {
		return nil, fmt.Errorf("integrity-invalid comparison: %w", invalid)
	}
	a, b := make([]float64, len(ours)), make([]float64, len(dll))
	for i := range ours {
		a[i], b[i] = *ours[i].Value, *dll[i].Value
	}
	ratios, err := pairedRatios(a, b)
	if err != nil {
		return nil, fmt.Errorf("integrity-invalid comparison: %w", err)
	}
	return ratios, nil
}
