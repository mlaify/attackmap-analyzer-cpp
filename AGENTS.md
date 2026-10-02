# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
C++ ecosystem coverage:

- **Web frameworks**: Crow (`CROW_ROUTE` + `.methods()` chain), Pistache (`Routes::Get/Post/...`), Drogon (`registerHandler`, `ADD_METHOD_TO`, `METHOD_ADD` with `/namespace/Class` prefix, `PATH_ADD`), cpprestsdk (`http_listener` URL extraction)
- **HTTP clients**: libcurl, cpr, cpprestsdk client
- **Databases**: libpqxx, MySQL X DevAPI, mongocxx, redis-plus-plus, SOCI, sqlite_orm
- **Auth/crypto**: OpenSSL (TLS / EVP / RAND), Botan (TLS / KDF / cipher), libsodium (`crypto_pwhash` → argon2; AEAD), Crypto++ (AES / SHA / Argon2 / HMAC), JWT C++ libs (`jwt::create`, `jwt::decode`)
- **Secrets**: `std::getenv` / `getenv` with secret-shaped names

## Out of scope (for now)
- Boost.Beast / Asio raw HTTP server detection — too low-level; would need flow analysis.
- Wt framework — too narrow.
- POCO Net per-route handler factory chains.
- oatpp `OATPP_API` macros — complex; only framework presence detected.
- Per-method handler extraction inside cpprestsdk `listener.support(method, lambda)` — only the listener URL is emitted as a Route.

## Marked experimental
Like the C analyzer, this one is marked `experimental=True`:
- C++'s template-heavy idioms make some imports / macros tricky to match without false positives.
- Confidence tiering is the primary defense — see below.

## Confidence policy
- Hash-class auth primitives (`crypto_pwhash`, `argon2id_hash_*`, `bcrypt_*`, `scrypt`, `Botan::Scrypt`, `CryptoPP::Argon2`) → 0.9
- Canonical TLS / cipher / JWT C++ API hits (`SSL_CTX_new`, `EVP_*`, `Botan::TLS::Server`, `jwt::create`, `CryptoPP::AES`) → 0.85
- Generic OpenSSL EVP / RAND → 0.8
- Keyword sweeps (`Authorization`, `Bearer`, `api_key`) → 0.6

## C-vs-C++ disambiguation
`.hpp`, `.hxx`, `.ipp`, `.tpp` are always C++. `.h` ownership is decided per repo, by the same rule in both the C and C++ analyzers, so exactly one of them analyzes each header whichever of `-m c` / `-m cpp` is selected:

- `.h` belongs to **C++** if the repo has any C++ source or header (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.ipp`, `.tpp`) or a `CMakeLists.txt` that enables CXX (`project(... CXX ...)`, `enable_language(CXX)` or `CMAKE_CXX_STANDARD`). A bare `project(foo)` doesn't count.
- Otherwise `.h` belongs to **C**.
- Files under directories either plugin prunes (`build/`, `third_party/`, `Debug/`, `Release/`, ...) are never markers.

In a mixed repo, `.c` files go to C, and `.cpp`/`.hpp`/... plus `.h` go to C++. Running only one of the two analyzers on a mixed repo leaves the other's files unanalyzed. It never double-counts them.

The rule's constants (`_CXX_MARKER_SUFFIXES`, `_CMAKE_CXX_PATTERN`) are mirrored in attackmap-analyzer-c. The C side also ignores markers under this plugin's extra `Debug/`/`Release/` skip dirs. `test_header_ownership_rule` uses the same case table in both repos. Change both together. Shared vocabulary (libcurl, OpenSSL, libsodium) appears in both analyzers' patterns. Since each file is analyzed by only one plugin, the merge's `(hint, file)` keys don't collide across them, except for the CMake `project:<name>` service hint, which collapses to one entry.

## Testing
Each new framework or extractor needs both:
- A positive test (signal fires on representative code).
- A negative test (e.g., `getenv("HOME")` is NOT a secret; a pure-C `.c` repo is NOT claimed by detect()).
