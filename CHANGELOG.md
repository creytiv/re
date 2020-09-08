# libre Changelog

All notable changes to libre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0.0] - 2020-09-08

### Added

- sip: add trace
- sdp: sdp_media_disabled API function [#2]
- tls: add tls_set_selfsigned_rsa [#6]
- tls: add functions to verify server cert, purpose and hostname [#10]
- http: client should set SNI [#10]
- http: client should use tls functions to verify server certs, purpose
  and hostname [#10]
- sipreg: add proxy expires field and get function [#13]
- sipreg: make re-register interval configurable [#13]

### Changed

- debian: Automatic cleanup after building debian package

### Fixed

- Set SDK path (SYSROOT) using xcrun (fix building on macOS 10.14)
- tcp: close socket on windows if connection is aborted or reset [#1]
- rtmp: Fix URL path parsing (creytiv#245)
- ice: various fixes [baresip/baresip#925]
- openssl/tls: replace deprecated openssl 1.1.0 functions [#5]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- juha-h
- Juha Heinanen
- Richard Aas
- Sebastian Reimers

[#13]: https://github.com/baresip/re/pull/13
[#10]: https://github.com/baresip/re/pull/10
[#6]: https://github.com/baresip/re/pull/6
[#5]: https://github.com/baresip/re/pull/5
[#2]: https://github.com/baresip/re/pull/2
[#1]: https://github.com/baresip/re/pull/1

[v1.0.0]: https://github.com/baresip/re/compare/v0.6.1...v1.0.0
[Unreleased]: https://github.com/baresip/re/compare/v1.0.0...HEAD
