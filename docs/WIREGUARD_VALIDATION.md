# WireGuard validation record — 2026-10-19

Base fork revision: `a75fee2` (`Linux GH Actions`). Implementation branch:
`feature/in-app-wireguard`.

## Completed

- Three portable CTest targets passed: configuration parsing, HTTP/RTSP route
  policy and packet sizing, and normal behavior with the backend compiled out.
  They were built in C++17 mode with Zig 0.16.0 on Windows.
- Full Nintendo Switch Release build succeeded, including the patched wg-nx,
  lwIP relay, Moonlight UI, HTTP integration and streaming integration.
  Target: `Moonlight.nro`; compiler: devkitA64 GCC 15.2.0; CMake: 3.31.
- The SDK came from the official `devkitpro/devkita64` amd64 image manifest
  `sha256:82575ea78651b530b2e232bb3799cfd1fe331514e053d5f724bb4b28191fb79d`.
  Image layers were verified by SHA-256 and unpacked into an isolated SDK.
  The container's conflicting `switch-enet` package was removed, matching the
  existing project workflow. Windows system packages were not changed.
- Verified that all six patched source files in the actual build staging tree
  match the reviewed patch output after line-ending normalization. CMake also
  checks patch markers and stops if Git silently skips the changes.
- Verified the final NRO header and the new `flushPendingTcpToRemote` symbol in
  the linked ELF. The build uses the repaired TCP relay.
- Static review covered TCP buffering/partial writes, pbuf ownership, TCP close
  callbacks, rekey locking, HTTP route rejection and tunnel shutdown order.

## Not established by these checks

No console, router, user profile or production Sunshine host was contacted.
Handshake interoperability, pairing, video/audio/controller behavior, bitrate,
latency, reconnect after network interruption, sleep/resume and prolonged rekey
behavior remain hardware test requirements. A successful build does not prove
those behaviors. See the console checklist in [`WIREGUARD.md`](WIREGUARD.md).

This version supports one IPv4 peer and one PC on standard GameStream ports.
DNS names for the WireGuard endpoint use the system resolver; slow DNS may delay
initialization and shutdown. Restart the app after sleep or a Wi-Fi change.
