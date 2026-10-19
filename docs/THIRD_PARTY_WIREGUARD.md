# WireGuard dependencies and notices

The client remains based on [XITRIX/Moonlight-Switch](https://github.com/XITRIX/Moonlight-Switch)
and retains its GPL-3.0-or-later source notices and existing dependencies.

The in-app tunnel links these additional components:

| Component | Pinned source | License and attribution |
| --- | --- | --- |
| wg-nx | `extern/wg-nx` at `753b9225302368f55f18ba180dd13e4138805253` | Copyright 2026 xlanor. LGPL-3.0-or-later; see its `LICENSE.md`, `COPYING.LESSER` and `COPYING`. |
| lwIP | wg-nx `library/lwip` at `4599f551dead9eac233b91c0b9ee5879f5d0620a` | BSD-style license, including Swedish Institute of Computer Science attribution; see `library/lwip/COPYING` and individual files. |
| Monocypher | wg-nx `library/crypto/monocypher.c` and `.h` | Copyright Loup Vaillant and contributors. BSD-2-Clause OR CC0-1.0; full notices remain in the source files. |
| BLAKE2s implementation | wg-nx `library/crypto/blake2s.c` and `.h` | Retains the original source-file notices. |

The loopback relay approach was studied in
[Artemis-Switch](https://github.com/antoinebou12/Artemis-Switch/blob/main/app/src/vpn/wg_nx_real.cpp).
The configuration parser, settings integration, routing and lifecycle code in this
fork are separate implementations. The library itself is patched at build time by
[`patches/wg-nx-reliability.patch`](../patches/wg-nx-reliability.patch);
the original submodule checkout is not modified. See
[`WG_NX_PATCHES.md`](WG_NX_PATCHES.md) for the changes and verification limits.

When distributing an NRO, include the applicable license notices and provide the
complete corresponding source of this fork, the pinned submodules, these patches,
and the build instructions. The build uses static linking; retain the material
needed to rebuild/relink the LGPL component. Do not distribute a source archive
that silently omits submodule contents or the patch.
