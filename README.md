# attackmap-analyzer-cpp

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

C++ ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from C++ source trees (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.ipp`, `.tpp`):

- **Web frameworks** — Crow (`CROW_ROUTE` macro with `.methods("POST"_method, ...)` chain), Pistache (`Routes::Get/Post/...`), Drogon (`registerHandler` with explicit method list, `ADD_METHOD_TO`, `METHOD_ADD` relative to the controller's `/namespace/Class` path, and `PATH_ADD`), cpprestsdk / Casablanca (`http_listener("https://...")` URL extraction), cpp-httplib (`svr.Get/Post/Put/Patch/Delete/Options` on a declared `httplib::Server`/`SSLServer`, regex paths kept as written), oat++ (`ENDPOINT`/`ENDPOINT_ASYNC`; an `AUTHORIZATION(...)` parameter sets `Route.auth = required`), restbed (`set_path`/`set_paths` on a `Resource` joined with its `set_method_handler` methods; `set_authentication_handler` on the resource or service sets `Route.auth = required`)
- **HTTP clients (external calls)** — libcurl (`CURLOPT_URL` literals), cpr (`cpr::Get(cpr::Url{"..."})`, `cpr::Post(...)`), cpprestsdk (`web::http::client::http_client(URL)`)
- **Databases** — libpqxx (`pqxx::connection`, `pqxx::work`), MySQL X DevAPI (`mysqlx::Session`), mongocxx (`mongocxx::client` + `mongocxx::uri`), redis-plus-plus (`sw::redis::Redis`), SOCI (`soci::session`), sqlite_orm (`sqlite_orm::make_storage`)
- **Auth/crypto** — OpenSSL (TLS / EVP / RAND), Botan (`TLS::Server`, `Cipher_Mode`, `PKCS5_PBKDF2`, `Scrypt`), libsodium (`crypto_pwhash` → argon2, `crypto_secretbox`, AEAD primitives), Crypto++ (`CryptoPP::AES`, `CryptoPP::SHA256`, `CryptoPP::Argon2`, `CryptoPP::HMAC`), JWT C++ libraries (`jwt::create`, `jwt::decode`, `jwt::verify`)
- **Secrets** — `std::getenv`, `getenv` with secret-shaped names
- **Service hints** — project name from `CMakeLists.txt` `project(NAME ...)` declaration
- **Dependencies (SBOM)** — vcpkg (`vcpkg.json`), Conan (`conanfile.txt`, `conanfile.py`, `conan.lock`) and CMake (`FetchContent_Declare`, `ExternalProject_Add`, `CPMAddPackage`, `find_package`), so `--cve` reaches native dependencies; unpinned CMake downloads are reported as supply-chain issues (see [Dependencies](#dependencies))

All emissions populate AttackMap's Signal v2 fields (line numbers + evidence snippets + confidence) so downstream insights can cite `path/to/file.cpp:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-cpp.git
```

The analyzer is registered with AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

This analyzer is **experimental and opt-in** (`enabled_by_default=False`): installing it does not make it run on every scan. Select it explicitly:

```bash
attackmap analyze /path/to/cpp/repo -m cpp
```

## Detection

`detect()` returns true when any `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.ipp`, or `.tpp` file is present, or `.h` headers in a CMake project that enables CXX (one walk), ignoring `_deps/`, `third_party/`, `external/`, `.cache/`, `Debug/`, `Release/` and AttackMap's shared skip list (`build/`, `out/`, `vendor/`, `node_modules/`, `.git/`, ...). Skip directories are matched only *inside* the repo, so a checkout under e.g. `/build/...` is still scanned. Files are walked with `attackmap.sdk.iter_repo_files`, which does not follow symlinks out of the repo, and read with `read_source`, which falls back to cp1252/latin-1 for legacy-encoded sources.

### `.h` ownership

`.h` ownership is decided per repo, by the same rule in both the C and C++ analyzers, so exactly one of them analyzes each header whichever of `-m c` / `-m cpp` is selected:

- `.h` belongs to **C++** if the repo has any C++ source or header (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.ipp`, `.tpp`) or a `CMakeLists.txt` that enables CXX (`project(... CXX ...)`, `enable_language(CXX)` or `CMAKE_CXX_STANDARD`). A bare `project(foo)` doesn't count.
- Otherwise `.h` belongs to **C**.
- Files under directories either plugin prunes (`build/`, `third_party/`, `Debug/`, `Release/`, ...) are never markers.

In a mixed repo, `.c` files go to C, and `.cpp`/`.hpp`/... plus `.h` go to C++. Running only one of the two analyzers on a mixed repo leaves the other's files unanalyzed. It never double-counts them.

A repo with only `.c` and `.h` files (and no C++ CMake) is not picked up here.

## Dependencies

`native_deps.py` emits `DependencyHint`s (mlaify/AttackMap#191). The module is shared verbatim with attackmap-analyzer-c. Core dedupes identical records when both analyzers run.

| Source | Ecosystem | Version | `dev` |
|---|---|---|---|
| `vcpkg.json` `dependencies` | `vcpkg` | `overrides` pin (`resolved=True`), else `>=` from `version>=`, else empty (the `builtin-baseline` decides; it's recorded in the evidence) | `"host": true` |
| `conanfile.txt` `[requires]` / `[tool_requires]` / `[build_requires]` / `[test_requires]` | `conan` | as written (`1.2.13`, `[>=1.80 <2.0]`) | tool/build/test sections |
| `conanfile.py` `requires = ...`, `self.requires("x/1.0")` and the tool/build/test forms (parsed with `ast`, never executed; comments and docstrings don't count) | `conan` | as written | tool/build/test |
| `conan.lock` (Conan 2 lists and Conan 1.x `graph_lock.nodes`) | `conan` | exact (`resolved=True`) | `build_requires`, build-context nodes |
| CMake `FetchContent_Declare` / `ExternalProject_Add` / `CPMAddPackage` | `cmake` | `GIT_TAG`, a CPM version, or a version in the archive URL | test/example manifests, test frameworks |
| CMake `find_package(Name [version] [EXACT])` | `cmake` | `>=version` / `==version`, ranges `1.2...<2.0` → `>=1.2,<2.0` | test/example manifests, test frameworks |

`cmake` is inventory-only in core: it has no OSV database, so `--cve` reports those dependencies as not CVE-checked. `conan` and `vcpkg` map to OSV ConanCenter and vcpkg. Build tools and CMake modules (`Threads`, `PkgConfig`, `Python3`, `Git`...) aren't dependencies.

**Unpinned downloads** are `SupplyChainIssue(kind="mutable_vcs_dependency")` records:

| Download | Severity |
|---|---|
| git download with no `GIT_TAG`, or a `GIT_TAG` that names a branch (`main`, `master`, `develop`...) | medium |
| any other tag or a short SHA | low |
| a full 40-hex commit SHA | not flagged |
| `URL` download without `URL_HASH`/`URL_MD5` | medium |

Values that are CMake variables (`${X}`) are never flagged. Comments, quoted strings and bracket arguments (`[[ ]]`) never contain commands. Malformed or deeply nested manifests are skipped.

## Coverage notes

- **Marked experimental**: like the C analyzer, regex coverage of C++ has more false-positive risk than language-specific analyzers with strict imports. Confidence tiering is the primary defense (0.9 for hash-class auth primitives, 0.85 for canonical TLS / cipher / JWT API hits, 0.6 for keyword sweeps).
- **Crow `.methods("X"_method)` chains**: when present, the route emits one Route per method in the chain. When absent, the route emits with method `ANY`.
- **Drogon `registerHandler`, `ADD_METHOD_TO`, `METHOD_ADD` and `PATH_ADD`**: all shapes are extracted, including the `{Drogon::Get, Drogon::Post}` initializer-list form and multi-method macros (`Put, Patch, "AuthFilter"`), which produce one Route per method (`ANY` when none is given). `METHOD_ADD` paths are prefixed with the controller's class path, e.g. `api::v1::User` → `/api/v1/User/{id}`.
- **cpp-httplib / oat++ / restbed routes** (`framework_routes.py`): a `.Get("/x")` call counts only on a receiver declared as a `Server` in the same file, so `httplib::Client` calls aren't routes. Servers from `std::make_unique/make_shared<httplib::Server>` count. Commented-out code and text inside string literals are ignored. A restbed `set_authentication_handler` guards its own `Resource` (even one with a non-literal path), or every resource when called on a declared `Service`; on any other receiver the route's auth stays `unknown`. oat++ and restbed paths are rooted (`users` → `/users`). A router-level prefix (oat++ `addController`, restbed `set_root`) isn't applied. Boost.Beast has no route registry (handlers compare `req.target()` by hand) and isn't extracted yet.
- **cpprestsdk listener routes**: only the path component of the listener's URL is extracted as a Route. Per-method handlers (`listener.support(methods::GET, ...)`) are not separately emitted — that would require tracking the listener's lifetime.
- **C++ shares vocabulary with C** (libcurl, OpenSSL, libsodium). Those patterns are duplicated here so a pure-C++ project without the C analyzer installed still gets full coverage. AttackMap's overlay deduplication handles double-firing.
- **Pure-template / header-only ORM** (sqlite_orm, sqlpp11): only basic detection via headers and `make_storage`; column-level extraction is out of scope.

## License

MIT
