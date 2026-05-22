# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-05-22

First tagged release. Implements the [libdns](https://github.com/libdns/libdns)
provider interfaces for the [AutoDNS](https://www.internetx.com/en/products/autodns/) API.

### Added

- `Provider` implementing `libdns.RecordGetter`, `RecordAppender`, `RecordSetter`,
  and `RecordDeleter`.
- `NewWithDefaults(username, password)` for the common case.
- `NewWithSDK(*sdk.SDK)` for callers that need to override `Endpoint`, `Context`,
  or `HttpClient` (e.g. sub-accounts).
- Standalone `sdk/` package exposing `CheckZone`, `GetZone`, `UpdateZone`, and
  `PatchZone` for direct API use.
- `AppendRecords` and `DeleteRecords` send a PATCH changeset
  (`resourceRecordsAdd` / `resourceRecordsRem`) instead of a full-zone PUT,
  avoiding lost-update races on concurrent edits.
- Apex and `www` A-record support via AutoDNS's `main.address` / `wwwInclude`
  shortcuts, surfaced as regular `libdns.Address` records on read.
- Optional `Provider.Zone` / `Provider.Nameserver` to skip the `CheckZone`
  lookup when the caller already knows them.
- Typed `sdk.AutoDNSError` carrying the per-message details from the API.
- Trailing-dot tolerance on zone names.
