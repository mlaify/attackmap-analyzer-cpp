# Changelog

All notable changes to `attackmap-analyzer-cpp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Native dependency inventory (mlaify/AttackMap#191).** A new `native_deps.py`, shared verbatim with attackmap-analyzer-c, emits `DependencyHint`s from:
  - `vcpkg.json`: dependencies, `version>=`, `overrides`, `host`, `builtin-baseline`;
  - Conan: `conanfile.txt`, `conanfile.py` (read as text, never executed) and `conan.lock`;
  - CMake: `FetchContent_Declare`, `ExternalProject_Add`, `CPMAddPackage` and `find_package`.

  `--cve` now reaches Conan and vcpkg dependencies. CMake ones are inventory-only. Git downloads on a branch or with no `GIT_TAG`, and archive URLs without `URL_HASH`, are reported as `mutable_vcs_dependency` supply-chain issues. Requires an AttackMap core with the `cmake` ecosystem and `SupplyChainIssue` in `attackmap.sdk` (mlaify/AttackMap#333).
- **Memory-safety and command-exec sinks (mlaify/AttackMap#189, #2).** The `native_sinks.py` pass, shared verbatim with attackmap-analyzer-c, emits `CodeWeakness` records for:
  - `unbounded_copy`: `gets`, unbounded `scanf` `%s`, and `strcpy`/`strcat`/`sprintf` from traced input;
  - `format_string`: non-constant printf-family formats;
  - `native_command_exec`: `system`/`popen`/`exec*`;
  - `tainted_copy_length`: input-controlled `memcpy` lengths;
  - `alloc_size_overflow`: unchecked `malloc(n * size)` / `new T[n * m]`.

  Sources are traced inside each function or lambda: request parameters of cpp-httplib, Crow, Drogon, Pistache, Boost.Beast, restbed and oat++ `ENDPOINT` handlers, the C framework accessors, socket reads, `std::cin`, argv, getenv and file reads. Severity and confidence follow the source: remote input high, local input medium, untraced low. Example code is capped at low and test/fuzz code is skipped. Requires an AttackMap core that exports `CodeWeakness` (mlaify/AttackMap#333).
- **cpp-httplib, oat++ and restbed routes (mlaify/AttackMap#191).** A new `framework_routes.py` extracts:
  - cpp-httplib `svr.Get/Post/Put/Patch/Delete/Options` on a declared `httplib::Server`/`SSLServer`. Client calls are excluded and regex paths are kept as written.
  - oat++ `ENDPOINT`/`ENDPOINT_ASYNC`. An `AUTHORIZATION(...)` parameter sets `Route.auth = "required"`.
  - restbed `set_path`/`set_paths` on a `Resource`, joined with its `set_method_handler` methods. A resource or service `set_authentication_handler` sets `Route.auth = "required"`.

  Framework hints were added for cpp-httplib and restbed. Validated on cpp-httplib, oat++ example-crud and restbed.

### Added

- `.h` headers are analyzed when the repo is C++ (any C++ source/header or a C++-enabled `CMakeLists.txt`), by the ownership rule shared with attackmap-analyzer-c. `detect()` also claims header-only C++ repos (`.h` + C++ CMake) (mlaify/attackmap-analyzer-c#2).
- Drogon `METHOD_ADD(Ctrl::fn, "/rel", Get)` routes, prefixed with the controller's `/namespace/Class` path, and `PATH_ADD("/path", ...)` for `HttpSimpleController` (mlaify/attackmap-analyzer-c#2).

### Changed

- **License metadata uses an SPDX expression (PEP 639).** `license = "MIT"` and `license-files = ["LICENSE"]` replace the deprecated `license = {text = "MIT"}` table, and the `License ::` classifier (which setuptools ≥ 77 rejects next to an expression) is gone. The build backend floor is now `setuptools>=77` (mlaify/AttackMap#259).
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
