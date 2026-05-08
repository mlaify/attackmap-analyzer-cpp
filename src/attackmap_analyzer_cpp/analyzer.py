"""C++ ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: Crow (CROW_ROUTE macro routes), Pistache (Routes::Get/Post/...),
  Drogon (registerHandler + ADD_METHOD_TO macro), cpprestsdk (http_listener URL +
  listener.support method handlers)
- HTTP clients (external calls): libcurl (CURLOPT_URL), cpprestsdk
  http_client(URL), cpr (cpr::Get/Post/Put/Delete with cpr::Url{...})
- Databases: libpqxx (pqxx::connection), MySQL X DevAPI (mysqlx::Session),
  mongocxx (mongocxx::client + mongocxx::uri), redis-plus-plus
  (sw::redis::Redis), SOCI (soci::session), sqlite_orm (header-only sqlite)
- Auth/crypto: OpenSSL (TLS / EVP / RAND), Botan (TLS / KDF / cipher),
  libsodium (crypto_pwhash, crypto_secretbox, AEAD), Crypto++
  (CryptoPP::AES/SHA256/Argon2), JWT C++ libraries (jwt::create, jwt::decode,
  jwt::verify)
- Secrets: getenv / std::getenv with secret-shaped names
- Service hints: project name from CMakeLists.txt project() declaration

C++ shares much of its data-plane vocabulary with C (libcurl, OpenSSL,
libsodium) — those patterns are duplicated here so a pure-C++ project
without the C analyzer installed still gets full coverage. AttackMap's
overlay deduplication handles cases where both analyzers fire on the
same evidence.
"""

from __future__ import annotations

import re
from pathlib import Path

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".ipp", ".tpp"}
SKIP_DIRS = {
    "build",
    ".git",
    "_deps",
    "third_party",
    "vendor",
    "external",
    ".cache",
    "out",
    "node_modules",
    "Debug",
    "Release",
}
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Crow: CROW_ROUTE(app, "/path") or CROW_ROUTE(app, "/path").methods("POST"_method)
CROW_ROUTE_PATTERN = re.compile(
    r'\bCROW_ROUTE\s*\(\s*\w+\s*,\s*"([^"]+)"\s*\)(?P<chain>(?:\s*\.\s*\w+\([^)]*\))*)',
)
# Crow .methods("POST"_method, "PUT"_method)
CROW_METHODS_PATTERN = re.compile(
    r'\.methods\s*\(\s*((?:"[A-Z]+"_method(?:\s*,\s*)?)+)\s*\)',
)

# Pistache: Routes::Get(router, "/path", handler), Routes::Post(...)
PISTACHE_ROUTE_PATTERN = re.compile(
    r'\b(?:Pistache::)?(?:Rest::)?Routes::(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*\w+\s*,\s*"([^"]+)"',
)

# Drogon: app().registerHandler("/path", handler, {Drogon::Get, Drogon::Post})
# Handler arg may be a lambda containing commas, so match non-greedy across the
# middle and anchor on the trailing `{ Drogon::* }` brace.
DROGON_REGISTER_PATTERN = re.compile(
    r'\bregisterHandler\s*\(\s*"([^"]+)"\s*,.+?,\s*\{([^}]*)\}\s*\)',
    re.DOTALL,
)

# Drogon annotation-style: METHOD_LIST_BEGIN ADD_METHOD_TO(controller::handler, "/path", Get) METHOD_LIST_END
DROGON_ADD_METHOD_PATTERN = re.compile(
    r'\bADD_METHOD_TO\s*\(\s*[^,]+,\s*"([^"]+)"\s*,\s*([A-Za-z]+)',
)

# cpprestsdk: web::http::experimental::listener::http_listener listener("https://example.com/api");
CPPRESTSDK_LISTENER_PATTERN = re.compile(
    r'\bhttp_listener\s+\w+\s*\(\s*(?:U\s*\(\s*)?"(https?://[^")]+)"',
)

# External HTTP calls
OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\bcurl_easy_setopt\s*\(\s*\w+\s*,\s*CURLOPT_URL\s*,\s*"(https?://[^"]+)"'),
    re.compile(r'\bcpr::(?:Get|Post|Put|Delete|Patch|Head)\s*\(\s*cpr::Url\s*\{\s*"(https?://[^"]+)"'),
    # Permissive http_client(URL) — namespace prefix may be `using`-elided.
    re.compile(r'\bhttp_client\s+\w+\s*\(\s*(?:U\s*\(\s*)?"(https?://[^")]+)"'),
    re.compile(r'\bRequest\s+\w+\s*\(\s*"(https?://[^"]+)"'),
]

# DBs
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bpqxx::connection\b|\bpqxx::work\b|#\s*include\s+["<]pqxx/'), "postgresql"),
    (re.compile(r'\bmysqlx::Session\b|\bmysqlx::SessionSettings\b|#\s*include\s+["<]mysqlx/'), "mysql"),
    (re.compile(r'\bmongocxx::client\b|\bmongocxx::uri\b|#\s*include\s+["<]mongocxx/'), "mongodb"),
    (re.compile(r'\bsw::redis::Redis\b|\bsw::redis::RedisCluster\b|#\s*include\s+["<]sw/redis\+\+'), "redis"),
    (re.compile(r'\bsoci::session\b|\bsoci::statement\b'), "sql"),
    (re.compile(r'\bsqlite_orm::make_storage\b|\bsqlite3_open(?:_v2)?\s*\('), "sqlite"),
    (re.compile(r'\bsql::mysql::MySQL_Driver\b|\bMySQL_Connection\b'), "mysql"),
]

# Auth / crypto
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'\bcrypto_pwhash(?:_argon2(?:i|id))?\s*\(|\bcrypto_pwhash_str\s*\('), "argon2", 0.9),
    (re.compile(r'\bargon2(?:i|d|id)?_hash\w*\s*\(|\bCryptoPP::Argon2\b'), "argon2", 0.9),
    (re.compile(r'\bbcrypt(?:_hashpw|_checkpw|_gensalt)?\s*\(|\bCryptoPP::BCrypt\b'), "bcrypt", 0.9),
    (re.compile(r'\bscrypt(?:_kdf)?\s*\(|\bBotan::Scrypt\b|\bCryptoPP::Scrypt\b'), "scrypt", 0.9),
    (re.compile(r'\bcrypto_secretbox\w*\s*\(|\bcrypto_aead_(?:chacha20poly1305|aes256gcm)\w*\s*\('), "libsodium_aead", 0.85),
    (re.compile(r'\bSSL_CTX_new\s*\(|\bSSL_new\s*\(|\bTLS_method\s*\(|\bTLS_(?:client|server)_method\s*\('), "openssl_tls", 0.85),
    (re.compile(r'\bEVP_PKEY_new\s*\(|\bEVP_(?:Encrypt|Decrypt)Init\w*\s*\('), "openssl_evp", 0.8),
    (re.compile(r'\bBotan::TLS::(?:Server|Client)\b|\bBotan::Cipher_Mode\b|\bBotan::PKCS5_PBKDF2\b'), "botan", 0.85),
    (re.compile(r'\bjwt::create\s*\(|\bjwt::decode\s*\(|\bjwt::verify\s*\(|#\s*include\s+["<]jwt-cpp/'), "jwt", 0.85),
    (re.compile(r'\bCryptoPP::AES\b|\bCryptoPP::SHA(?:256|384|512|3)\b|\bCryptoPP::HMAC\b'), "cryptopp", 0.85),
    (re.compile(r'\bAuthorization\b'), "authorization_header", 0.6),
    (re.compile(r'\bBearer\b'), "bearer_token", 0.6),
    (re.compile(r'\bapi[_-]?key\b', re.IGNORECASE), "api_key", 0.6),
]

FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bcrow::SimpleApp\b|#\s*include\s+["<]crow\.h|\bCROW_ROUTE\s*\('), "crow"),
    (re.compile(r'\bPistache::(?:Http|Rest)\b|#\s*include\s+["<]pistache/'), "pistache"),
    (re.compile(r'\bdrogon::HttpAppFramework\b|\bapp\(\)\.registerHandler\b|#\s*include\s+["<]drogon/'), "drogon"),
    (re.compile(r'\bweb::http::experimental::listener\b|#\s*include\s+["<]cpprest/'), "cpprestsdk"),
    (re.compile(r'\bboost::beast\b|#\s*include\s+["<]boost/beast'), "boost-beast"),
    (re.compile(r'\bPoco::Net::HTTPServer\b|#\s*include\s+["<]Poco/Net/'), "poco-net"),
    (re.compile(r'\boatpp::web::server\b|#\s*include\s+["<]oatpp/'), "oatpp"),
    (re.compile(r'#\s*include\s+["<]openssl/'), "openssl"),
    (re.compile(r'#\s*include\s+["<]botan/'), "botan"),
    (re.compile(r'#\s*include\s+["<]sodium\.h'), "libsodium"),
    (re.compile(r'#\s*include\s+["<]cryptopp/'), "cryptopp"),
    (re.compile(r'#\s*include\s+["<]curl/curl\.h|#\s*include\s+["<]cpr/'), "libcurl"),
    (re.compile(r'#\s*include\s+["<]pqxx/'), "libpqxx"),
    (re.compile(r'#\s*include\s+["<]mongocxx/'), "mongocxx"),
    (re.compile(r'#\s*include\s+["<]sw/redis\+\+'), "redis-plus-plus"),
]

ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bapp\.(?:port|bindaddr|run|multithreaded)\(.*?\)\.run\s*\(\s*\)', re.DOTALL), "crow_app_run"),
    (re.compile(r'\bcrow::SimpleApp\b'), "crow_app"),
    (re.compile(r'\b\w+\.serve\s*\(\s*\)', re.IGNORECASE), "pistache_serve"),
    (re.compile(r'\bapp\(\)\.run\s*\(\s*\)|\bdrogon::app\(\)\.run\b'), "drogon_run"),
    (re.compile(r'\blistener\.open\s*\(\s*\)\.wait\s*\(\s*\)|\blistener\.open\s*\(\s*\)\.then\b'), "cpprestsdk_listener_open"),
    (re.compile(r'\bPoco::Net::HTTPServer\s+\w+'), "poco_http_server"),
]

# Secrets via getenv / std::getenv
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\b(?:std::)?(?:secure_)?getenv\s*\(\s*"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
]


def _line_of(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _project_name_from_cmake(cmake_path: Path) -> str | None:
    if not cmake_path.exists():
        return None
    try:
        text = cmake_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    match = re.search(r"\bproject\s*\(\s*([A-Za-z0-9_\-]+)", text)
    if match:
        return match.group(1)
    return None


class CppAnalyzer:
    metadata = AnalyzerMetadata(
        name="cpp",
        display_name="C++ Analyzer",
        version="0.1.0",
        description="C++ analyzer covering Crow, Pistache, Drogon, cpprestsdk, libcurl/cpr, OpenSSL/Botan/libsodium/Crypto++, libpqxx/mongocxx/redis-plus-plus.",
        scope="C++ source trees and CMake projects. Detects modern HTTP frameworks and common DB / crypto libraries.",
        targets=["cpp", "c++", "crow", "pistache", "drogon", "cpprestsdk"],
        languages=["cpp"],
        priority=20,
        experimental=True,  # Like the C analyzer; regex coverage of C++ is more leaky than of stricter ecosystems.
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix in CODE_SUFFIXES:
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        for cmake in root.rglob("CMakeLists.txt"):
            if any(part in SKIP_DIRS for part in cmake.parts):
                continue
            project = _project_name_from_cmake(cmake)
            if project:
                self._append_unique_service(result, f"project:{project}", str(cmake.relative_to(root)))

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            if file_path.suffix not in CODE_SUFFIXES:
                continue

            result.files_scanned += 1
            if "cpp" not in result.languages:
                result.languages.append("cpp")

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        # Crow: CROW_ROUTE(app, "/x").methods("POST"_method, "PUT"_method)
        for match in CROW_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            chain = match.group("chain") or ""
            line = _line_of(content, match.start())
            methods: set[str] = set()
            methods_match = CROW_METHODS_PATTERN.search(chain)
            if methods_match:
                methods = {m.upper() for m in re.findall(r'"([A-Z]+)"_method', methods_match.group(1))}
            if not methods:
                methods = {"ANY"}
            for method in sorted(methods):
                self._append_unique_route(result, path, method, relative, line)

        # Pistache: Routes::Get(router, "/x", handler)
        for match in PISTACHE_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # Drogon registerHandler with explicit method list: {Drogon::Get, Drogon::Post}
        for match in DROGON_REGISTER_PATTERN.finditer(content):
            path = match.group(1)
            methods_blob = match.group(2)
            methods = {
                m.upper()
                for m in re.findall(r'\b(?:Drogon::)?(Get|Post|Put|Delete|Patch|Head|Options)\b', methods_blob)
            }
            line = _line_of(content, match.start())
            if not methods:
                methods = {"ANY"}
            for method in sorted(methods):
                self._append_unique_route(result, path, method, relative, line)

        # Drogon ADD_METHOD_TO macro: ADD_METHOD_TO(ctrl::handler, "/path", Get)
        for match in DROGON_ADD_METHOD_PATTERN.finditer(content):
            path, method = match.group(1), match.group(2).upper()
            self._append_unique_route(result, path, method, relative, _line_of(content, match.start()))

        # cpprestsdk listener URL — the listener is constructed with the full URL
        # which we treat as both an entrypoint and a route (path part).
        for match in CPPRESTSDK_LISTENER_PATTERN.finditer(content):
            url = match.group(1)
            # Best-effort: extract the path component of the URL.
            path_match = re.search(r"https?://[^/]+(/[^?]*)", url)
            if path_match:
                path = path_match.group(1) or "/"
                self._append_unique_route(result, path, "ANY", relative, _line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1)
                self._append_unique_secret(
                    result, name, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                if not (target.startswith("http://") or target.startswith("https://")):
                    continue
                self._append_unique_external(
                    result, target, relative,
                    _line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int | None) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["CppAnalyzer"]
