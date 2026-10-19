# wg-nx reliability patch

`patches/wg-nx-reliability.patch` carries the local reliability changes for the
`extern/wg-nx` source at upstream revision `753b9225302368f55f18ba180dd13e4138805253`.
It is applied to a disposable build copy; the Git submodule stays pristine.

The patch makes the TCP relay retain local-stream bytes until `tcp_write` accepts
them and retain remote-stream bytes until the local socket accepts them. It
respects partial writes and `EAGAIN`, applies lwIP receive-window backpressure,
handles both FIN directions, and retries data while lwIP has no send capacity.
On a fully drained TCP close, it detaches PCB callbacks before close, then closes
the local socket and removes the flow; if lwIP returns `ERR_MEM`, it restores
callbacks and retries later. The UDP relay copies complete chained pbufs and
checks the reply source against the configured peer address and target port. It
also keeps each TCP listener's configured destination port.
The lwIP Switch architecture header defines `SSIZE_MAX` only if the SDK headers
have not already provided it.

In wg-nx, the patch serializes session keys, counters, replay state, callback
registration, and rekey updates. It commits the peer's transport index only
after the handshake response authenticates, preserves the established local
index over failed rekey attempts, authenticates empty keepalives, and limits
only the initial connection handshake to three attempts. The timer-driven
rekey retry policy remains unchanged. Session locks are released while waiting
for handshake responses. Failed `wg_init` paths wipe copied private and
preshared keys before freeing the tunnel.

## Apply to a build copy

The patch paths are relative to the wg-nx source root, which contains `src/` and
`lwip-relay/`. In PowerShell, point `$wgNxRoot` at the disposable copy and run:

```powershell
$wgNxRoot = '<build-dir>\wg-nx'
$patchFile = (Resolve-Path '.\patches\wg-nx-reliability.patch').Path
git -C $wgNxRoot apply --check $patchFile
if ($LASTEXITCODE -ne 0) { throw 'wg-nx patch does not apply cleanly' }
git -C $wgNxRoot apply $patchFile
```

Run `git -C $wgNxRoot diff --check` afterward. To verify the patch against a
fresh checkout, first check out the base revision above; applying it to a
different revision may require review and adjustment.

## Licensing and validation

The patch changes existing wg-nx files and retains their SPDX and copyright
headers. Keep the upstream `COPYING` and `COPYING.LESSER` files with any
distribution of the modified library; wg-nx is LGPL-3.0-or-later. The bundled
lwIP source has its separate license and is not changed by this patch.

The isolated source diff passed `git diff --check`. On 2026-10-19, the patched
backend and complete Moonlight NRO built successfully with devkitA64 GCC 15.2.0.
All six staged patched files were compared with the reviewed patch output, and
the final ELF contains the new TCP buffering helper. See
[`WIREGUARD_VALIDATION.md`](WIREGUARD_VALIDATION.md) for the build record.
This patch has not been exercised on Switch hardware. A streaming
test should cover partial TCP writes/backpressure, TCP half-close, large UDP
replies, repeated rekey timeouts followed by recovery, handshake cookie retry,
and shutdown while packets are in flight.
