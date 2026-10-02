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

- **Web frameworks** — Crow (`CROW_ROUTE` macro with `.methods("POST"_method, ...)` chain), Pistache (`Routes::Get/Post/...`), Drogon (`registerHandler` with explicit method list AND `ADD_METHOD_TO` macro), cpprestsdk / Casablanca (`http_listener("https://...")` URL extraction)
- **HTTP clients (external calls)** — libcurl (`CURLOPT_URL` literals), cpr (`cpr::Get(cpr::Url{"..."})`, `cpr::Post(...)`), cpprestsdk (`web::http::client::http_client(URL)`)
- **Databases** — libpqxx (`pqxx::connection`, `pqxx::work`), MySQL X DevAPI (`mysqlx::Session`), mongocxx (`mongocxx::client` + `mongocxx::uri`), redis-plus-plus (`sw::redis::Redis`), SOCI (`soci::session`), sqlite_orm (`sqlite_orm::make_storage`)
- **Auth/crypto** — OpenSSL (TLS / EVP / RAND), Botan (`TLS::Server`, `Cipher_Mode`, `PKCS5_PBKDF2`, `Scrypt`), libsodium (`crypto_pwhash` → argon2, `crypto_secretbox`, AEAD primitives), Crypto++ (`CryptoPP::AES`, `CryptoPP::SHA256`, `CryptoPP::Argon2`, `CryptoPP::HMAC`), JWT C++ libraries (`jwt::create`, `jwt::decode`, `jwt::verify`)
- **Secrets** — `std::getenv`, `getenv` with secret-shaped names
- **Service hints** — project name from `CMakeLists.txt` `project(NAME ...)` declaration

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

`detect()` returns true when any `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.ipp`, or `.tpp` file is present, ignoring `_deps/`, `third_party/`, `external/`, `.cache/`, `Debug/`, `Release/` and AttackMap's shared skip list (`build/`, `out/`, `vendor/`, `node_modules/`, `.git/`, ...). Skip directories are matched only *inside* the repo, so a checkout under e.g. `/build/...` is still scanned. Files are walked with `attackmap.sdk.iter_repo_files`, which does not follow symlinks out of the repo, and read with `read_source`, which falls back to cp1252/latin-1 for legacy-encoded sources.

This analyzer **does not** claim `.h` files — those are handled by the C analyzer (`attackmap-analyzer-c`). A repo with only `.c` and `.h` files is not picked up here.

## Coverage notes

- **Marked experimental**: like the C analyzer, regex coverage of C++ has more false-positive risk than language-specific analyzers with strict imports. Confidence tiering is the primary defense (0.9 for hash-class auth primitives, 0.85 for canonical TLS / cipher / JWT API hits, 0.6 for keyword sweeps).
- **Crow `.methods("X"_method)` chains**: when present, the route emits one Route per method in the chain. When absent, the route emits with method `ANY`.
- **Drogon `registerHandler` and `ADD_METHOD_TO`**: both shapes are extracted, including the `{Drogon::Get, Drogon::Post}` initializer-list form which produces multiple Routes.
- **cpprestsdk listener routes**: only the path component of the listener's URL is extracted as a Route. Per-method handlers (`listener.support(methods::GET, ...)`) are not separately emitted — that would require tracking the listener's lifetime.
- **C++ shares vocabulary with C** (libcurl, OpenSSL, libsodium). Those patterns are duplicated here so a pure-C++ project without the C analyzer installed still gets full coverage. AttackMap's overlay deduplication handles double-firing.
- **Pure-template / header-only ORM** (sqlite_orm, sqlpp11): only basic detection via headers and `make_storage`; column-level extraction is out of scope.

## License

MIT
