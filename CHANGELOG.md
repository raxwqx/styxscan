# Changelog

## 5.0.0 - 2026-11-15

- Bounded captured HTTP response content to 1 MiB to prevent unexpectedly large responses from exhausting memory.
- TLS inspection now skips plain HTTP targets and honors the requested timeout.
- Updated package and HTTP user-agent version to 5.0.0.
