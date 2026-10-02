# Changelog

All notable changes to `attackmap-analyzer-cpp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `.h` headers are analyzed when the repo is C++ (any C++ source/header or a C++-enabled `CMakeLists.txt`), by the ownership rule shared with attackmap-analyzer-c. `detect()` also claims header-only C++ repos (`.h` + C++ CMake) (mlaify/attackmap-analyzer-c#2).
- Drogon `METHOD_ADD(Ctrl::fn, "/rel", Get)` routes, prefixed with the controller's `/namespace/Class` path, and `PATH_ADD("/path", ...)` for `HttpSimpleController` (mlaify/attackmap-analyzer-c#2).

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a local `rglob` + `SKIP_DIRS` walk (mlaify/AttackMap#253).
- The analyzer is now opt-in while experimental (`enabled_by_default=False`): run it with `attackmap analyze <repo> -m cpp` (mlaify/AttackMap#221).

### Fixed

- Drogon `ADD_METHOD_TO` now emits every listed method (`Get, Post`) instead of only the first, ignores filter-name strings, and no longer turns `drogon::Post` into method `DROGON` (mlaify/attackmap-analyzer-c#2).
- A repo checked out under a directory named like a skip dir (e.g. `/build/...`, `.../out/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo are no longer followed and analyzed.
- cp1252/latin-1 encoded sources are analyzed instead of silently dropped, and an unreadable file no longer raises out of `analyze()`.
- `files_scanned` no longer counts files that could not be read.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. C++ ecosystem analyzer plugin for AttackMap (Crow, Pistache, Drogon, cpprestsdk; libcurl/cpr; OpenSSL/Botan/libsodium/Crypto++; libpqxx/mongocxx/redis-plus-plus).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-cpp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-cpp/releases/tag/v0.1.0
