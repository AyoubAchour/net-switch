package usage

import "math"

// Specialized V8/fdlibm pow(0.5, y). log2(0.5) is exactly -1, so only
// the split-product and exponential stages are needed. Explicit float64
// products prohibit FMA fusion, including on ARM64. This keeps exact parity;
// no tolerance is applied to peak samples or accumulated usage.
// Source: nodejs/node v24.18.0 deps/v8/src/base/ieee754.cc, legacy::pow.
//
// Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
// Developed at SunSoft, a Sun Microsystems, Inc. business.
// Permission to use, copy, modify, and distribute this software is freely
// granted, provided that this notice is preserved.
// Modified significantly by Google Inc.
// Copyright 2016 the V8 project authors. All rights reserved.
// See V8-LICENSE.txt for the V8 BSD license.
func fade(y float64) float64 {
	if y == 0 {
		return 1
	}
	if y == -1 {
		return 2
	}
	if y == 1 {
		return 0.5
	}
	if y == 2 {
		return 0.25
	}
	if y == 0.5 {
		return math.Sqrt(0.5)
	}
	if math.IsNaN(y) {
		return y
	}
	if y <= -1024 {
		return math.Inf(1)
	}
	if y >= 1075 {
		return 0
	}
	high := func(x float64) float64 { return math.Float64frombits(math.Float64bits(x) & 0xffffffff00000000) }
	y1 := high(y)
	pl, ph := -(y - y1), -y1
	z := pl + ph
	j := int32(math.Float64bits(z) >> 32)
	i := uint32(j) & 0x7fffffff
	k := int(i>>20) - 0x3ff
	n := 0
	if i > 0x3fe00000 {
		rounded := uint32(j) + (uint32(0x00100000) >> uint(k+1))
		k = int((rounded&0x7fffffff)>>20) - 0x3ff
		t := math.Float64frombits(uint64(rounded & ^(uint32(0x000fffff)>>uint(k))) << 32)
		n = int(((rounded & 0x000fffff) | 0x00100000) >> uint(20-k))
		if j < 0 {
			n = -n
		}
		ph -= t
	}
	const lg2 = 6.93147180559945286227e-01
	const lg2h = 6.93147182464599609375e-01
	const lg2l = -1.90465429995776804525e-09
	const p1 = 1.66666666666666019037e-01
	const p2 = -2.77777777770155933842e-03
	const p3 = 6.61375632143793436117e-05
	const p4 = -1.65339022054652515390e-06
	const p5 = 4.13813679705723846039e-08
	t := high(pl + ph)
	u := float64(t * lg2h)
	v := float64((pl-(t-ph))*lg2) + float64(t*lg2l)
	z = u + v
	w := v - (z - u)
	t = float64(z * z)
	poly := p4 + float64(t*p5)
	poly = p3 + float64(t*poly)
	poly = p2 + float64(t*poly)
	poly = p1 + float64(t*poly)
	t1 := z - float64(t*poly)
	r := float64(z*t1) / ((t1 - 2) - (w + float64(z*w)))
	z = 1 - (r - z)
	return math.Ldexp(z, n)
}
