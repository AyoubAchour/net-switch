# Third-party software

Net Switch's own code is under the MIT license (see `LICENSE`). The installer
also ships the separate programs below, each under its own license. They run as
separate programs; Net Switch does not modify them. The one exception is the Go
code compiled into Net Switch's own helper program (see the end). "MIT" applies
to Net Switch's code only, not to the installer as a whole.

## sing-box 1.14.2

- What it does here: the routing engine (`engine\sing-box.exe`).
- Copyright (C) 2022 by nekohasekai. Licensed under the GNU General Public
  License, version 3 or later, with an additional term:
  > In addition, no derivative work may use the name or imply association with
  > this application without prior consent.

  Net Switch is not affiliated with or endorsed by the sing-box project. It
  runs the unmodified official release.
- License texts in the installed copy: `licenses\GPL-3.0.txt` and
  `licenses\sing-box-LICENSE.txt`, and `engine\LICENSE`.
- Source: the exact version is
  [v1.14.2](https://github.com/SagerNet/sing-box/tree/v1.14.2). Each Net Switch
  release also attaches `sing-box-1.14.2-source-with-deps.tar.gz`, that source
  with its Go dependencies included.

## libcronet.dll

- What it does here: a network library that ships with the sing-box Windows
  release (`engine\libcronet.dll`).
- It comes from [cronet-go](https://github.com/SagerNet/cronet-go), copyright
  (C) 2022 by nekohasekai, under the GNU General Public License version 3 or
  later (`licenses\cronet-go-LICENSE.txt`).
- The DLL itself is Chromium's Cronet network library (Chromium 150.0.7871.63),
  built by cronet-go from the
  [naiveproxy](https://github.com/SagerNet/naiveproxy/tree/72a06c9fca0e2d228588c7f3074bf7efff3ff686)
  source tree. Chromium is under a BSD-style license and includes code from
  other projects under their own licenses. The license, author and credit files
  from that source tree are in `licenses\cronet-native\`.
- Source: cronet-go commit
  [`0d28acc`](https://github.com/SagerNet/cronet-go/tree/0d28acc44093df24b2526dea3d6ffefd6b0a54f0),
  as pinned by sing-box 1.14.2's `go.mod` (included in the source bundle
  above). The Windows DLL was built at cronet-go commit
  [`049f290`](https://github.com/SagerNet/cronet-go/tree/049f2909701ca088c9569f6b303bba5376a2b2ff)
  and published in commit
  [`c10c03c`](https://github.com/SagerNet/cronet-go/commit/c10c03c318db6d47bec8705c8290bad34bc32b64).
  Each release's `sources.txt` lists these pins.

## Wintun 0.14.1

- What it does here: the Windows driver behind the virtual network adapter.
  sing-box carries it inside `sing-box.exe` (through
  [sing-tun](https://github.com/SagerNet/sing-tun)); it matches the official
  [wintun-0.14.1.zip](https://www.wintun.net/builds/wintun-0.14.1.zip) build.
- Copyright (C) WireGuard LLC. Distributed under the Wintun prebuilt-binaries
  license, which allows shipping it unmodified with other software:
  `licenses\wintun-LICENSE.txt`.

## Node.js

- What it does here: runs Net Switch (`runtime\node.exe`).
- Copyright Node.js contributors, under the MIT license, with notices for the
  components Node.js includes.
- License text in the installed copy: `runtime\LICENSE` and
  `licenses\node-LICENSE.txt`, taken unchanged from the official Node.js build.

## Lucide icons

- What it does here: the shapes of several icons in the window and tray.
- ISC license (with some icons from Feather under MIT): see
  `licenses\lucide-ISC.txt`.

## Go runtime and golang.org/x/sys

- What it does here: `helper\netswitch-helper.exe` is Net Switch's own small
  program (its source is in the repository's `helper` folder) that reads the
  line meters and the connections that go around routing. It is written in Go, so the Go runtime
  and standard library (Go 1.27.2) and
  [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) v0.49.0 are compiled
  into it, unmodified.
- Copyright 2009 The Go Authors. Both are under the same BSD-style
  (3-clause) license. License text in the installed copy:
  `licenses\go-LICENSE.txt`, taken unchanged from the official Go release.
  golang.org/x/sys ships the same text.

## Net Switch 1.0 engine core (not yet shipped)

The new engine's own code is MIT licensed. Its root Go module includes these
dependencies; this does not replace the 0.3.x programs listed above.

- gvisor.dev/gvisor `v0.0.0-20261017122056-1b7906fdee8c`, Apache-2.0.
  Copyright The gVisor Authors. License and authors are preserved in
  `third_party/gvisor/LICENSE` and `AUTHORS`, and in the generated vendor tree.
  Net Switch modifies seven TCP files for opt-in local-app close admission, TIME_WAIT handling and buffer accounting;
  each has a modification notice. The reproducible patch is
  `third_party/gvisor-timewait.patch`.
- github.com/google/btree v1.1.2, Apache-2.0; see
  `vendor/github.com/google/btree/LICENSE`.
- golang.org/x/exp `v0.0.0-20250711185948-6ae5c78190dc`,
  golang.org/x/sys v0.48.0 and golang.org/x/time v0.15.0, BSD-3-Clause;
  see each module's LICENSE and PATENTS in `vendor/golang.org/x/`.
- Go 1.27.2 runtime and standard library, BSD-3-Clause;
  see the Go toolchain's LICENSE and PATENTS.
