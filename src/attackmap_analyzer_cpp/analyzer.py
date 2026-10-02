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

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, read_source, rel

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
# C++-specific additions to the shared skip list (which already covers build/,
# out/, vendor/, node_modules/, .git/, ...). Matched against directory names
# *inside* the repo only.
SKIP_DIRS = DEFAULT_SKIP_DIRS | {"_deps", "third_party", "external", ".cache", "Debug", "Release"}

# ---------- .h ownership (shared rule with attackmap-analyzer-c) ----------
#
# A ``.h`` header is either C or C++, and only one analyzer may claim it, or a
# C++ project's headers (e.g. Drogon controllers, whose routes live in the
# header) get analyzed as C and labelled language ``c``. The rule is decided
# per repo and is mirrored *verbatim* in attackmap-analyzer-c, so both
# plugins agree whichever of ``-m c`` / ``-m cpp`` is selected:
#
#   ``.h`` belongs to C++ if the repo has any C++ source/header (the suffixes
#   below) or a CMakeLists.txt that enables CXX (``project(... CXX ...)``,
#   ``enable_language(CXX)`` or ``CMAKE_CXX_STANDARD``); otherwise to C.
#
# Keep ``_CXX_MARKER_SUFFIXES`` and ``_CMAKE_CXX_PATTERN`` in sync with the C
# plugin (which also ignores markers under this plugin's extra
# ``Debug``/``Release`` skip dirs).
_CXX_MARKER_SUFFIXES = CODE_SUFFIXES
_CMAKE_CXX_PATTERN = re.compile(
    r"\b(?i:project)\s*\([^)]*\bCXX\b"
    r"|\b(?i:enable_language)\s*\(\s*CXX\b"
    r"|\bCMAKE_CXX_STANDARD\b",
)
_HEADER_SUFFIX = ".h"
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

# Drogon HttpController: METHOD_LIST_BEGIN ... METHOD_LIST_END with
#   ADD_METHOD_TO(Ctrl::handler, "/abs/path", Get, Post, "Filter")  - absolute path
#   METHOD_ADD(Ctrl::handler, "/rel/{id}", Get)                      - relative to
#     the controller's class path, /<namespace parts>/<ClassName>
# and HttpSimpleController: PATH_ADD("/abs/path", Get, "Filter").
# The trailing group is the rest of the argument list (methods and filters).
DROGON_ADD_METHOD_PATTERN = re.compile(
    r'\bADD_METHOD_TO\s*\(\s*[^,()]+,\s*"([^"]*)"\s*((?:,[^()]*)?)\)',
)
DROGON_METHOD_ADD_PATTERN = re.compile(
    r'\bMETHOD_ADD\s*\(\s*(?:(?:::)?(\w+(?:::\w+)*)::)?\w+\s*,\s*"([^"]*)"\s*((?:,[^()]*)?)\)',
)
DROGON_PATH_ADD_PATTERN = re.compile(
    r'\bPATH_ADD\s*\(\s*"([^"]*)"\s*((?:,[^()]*)?)\)',
)
_DROGON_METHOD_RE = re.compile(r'\b(?:drogon::)?(Get|Post|Put|Delete|Patch|Head|Options)\b')
# class Foo : public drogon::HttpController<Foo>   (also final / HttpSimpleController)
DROGON_CONTROLLER_PATTERN = re.compile(
    r'\b(?:class|struct)\s+(\w+)\s*(?:final\s*)?:\s*public\s+(?:::)?(?:drogon::)?Http(?:Simple)?Controller\s*<',
)
_NAMESPACE_OR_BRACE_RE = re.compile(r'\bnamespace\s+((?:\w+::)*\w+)\s*\{|[{}]')

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


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    # Kept local rather than ``attackmap.sdk.line_snippet(content, line_of(...))``:
    # the SDK helper indexes ``str.splitlines()``, which also breaks on form
    # feeds and lone ``\r``, so its line numbering can disagree with
    # ``line_of`` (which counts ``\n`` only).
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _project_name_from_cmake(text: str) -> str | None:
    match = re.search(r"\bproject\s*\(\s*([A-Za-z0-9_\-]+)", text)
    if match:
        return match.group(1)
    return None


def _drogon_methods(args: str) -> list[str]:
    """Sorted HTTP methods named in a Drogon macro's trailing arguments
    (filter-name strings are ignored); ``["ANY"]`` when none constrain it."""
    unquoted = re.sub(r'"[^"]*"', "", args)
    methods = sorted({m.upper() for m in _DROGON_METHOD_RE.findall(unquoted)})
    return methods or ["ANY"]


def _namespaces_at(content: str, offset: int) -> list[str]:
    """Namespace names enclosing ``offset`` (outermost first), from
    ``namespace a { namespace b {`` or C++17 ``namespace a::b {``."""
    stack: list[str | None] = []
    for match in _NAMESPACE_OR_BRACE_RE.finditer(content, 0, offset):
        if match.group(1):
            stack.append(match.group(1))
        elif match.group(0) == "{":
            stack.append(None)
        elif stack:
            stack.pop()
    parts: list[str] = []
    for name in stack:
        if name:
            parts.extend(name.split("::"))
    return parts


def _drogon_controller_paths(content: str) -> dict[str, str]:
    """Map each HttpController class name to its Drogon class path,
    ``/<namespace parts>/<ClassName>`` (e.g. ``api::v1::User`` -> ``/api/v1/User``)."""
    paths: dict[str, str] = {}
    for match in DROGON_CONTROLLER_PATTERN.finditer(content):
        name = match.group(1)
        paths[name] = "/" + "/".join([*_namespaces_at(content, match.start()), name])
    return paths


def _join_drogon_path(prefix: str, path: str) -> str:
    if not path:
        return prefix
    return prefix.rstrip("/") + (path if path.startswith("/") else "/" + path)


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
        enabled_by_default=False,  # opt-in via `-m cpp` while experimental (AttackMap#221)
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        # One walk. Any C++ source/header claims the repo; so do .h headers in
        # a CMake project that enables CXX (header-only C++ with .h names).
        # Suffixes are matched case-sensitively, as before; the SDK match is
        # case-insensitive, so filter again.
        has_header = False
        cmake_cxx = False
        for path in iter_repo_files(
            root, suffixes=CODE_SUFFIXES | {_HEADER_SUFFIX}, names={"CMakeLists.txt"}, skip_dirs=SKIP_DIRS
        ):
            if path.suffix in CODE_SUFFIXES:
                return True
            if path.name == "CMakeLists.txt":
                text = read_source(path)
                cmake_cxx = cmake_cxx or (text is not None and _CMAKE_CXX_PATTERN.search(text) is not None)
            elif path.suffix == _HEADER_SUFFIX:
                has_header = True
        return has_header and cmake_cxx

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # One walk collects sources, headers and CMake files; .h headers are
        # analyzed only when the repo is C++ (see the module-level rule).
        candidates: list[Path] = []
        cxx_repo = False
        for file_path in iter_repo_files(
            root,
            suffixes=CODE_SUFFIXES | {_HEADER_SUFFIX},
            names={"CMakeLists.txt"},
            skip_dirs=SKIP_DIRS,
        ):
            if file_path.name == "CMakeLists.txt":
                text = read_source(file_path)
                if text is None:
                    continue
                project = _project_name_from_cmake(text)
                if project:
                    self._append_unique_service(result, f"project:{project}", rel(file_path, root))
                if _CMAKE_CXX_PATTERN.search(text):
                    cxx_repo = True
                continue
            if file_path.suffix in _CXX_MARKER_SUFFIXES:
                cxx_repo = True
                candidates.append(file_path)
            elif file_path.suffix == _HEADER_SUFFIX:
                candidates.append(file_path)

        for file_path in candidates:
            if file_path.suffix == _HEADER_SUFFIX and not cxx_repo:
                continue  # owned by the C analyzer
            content = read_source(file_path)
            if content is None:
                continue

            result.files_scanned += 1
            if "cpp" not in result.languages:
                result.languages.append("cpp")

            relative = rel(file_path, root)
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
            line = line_of(content, match.start())
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
            self._append_unique_route(result, path, method, relative, line_of(content, match.start()))

        # Drogon registerHandler with explicit method list: {Drogon::Get, Drogon::Post}
        for match in DROGON_REGISTER_PATTERN.finditer(content):
            path = match.group(1)
            methods_blob = match.group(2)
            methods = {
                m.upper()
                for m in re.findall(r'\b(?:Drogon::)?(Get|Post|Put|Delete|Patch|Head|Options)\b', methods_blob)
            }
            line = line_of(content, match.start())
            if not methods:
                methods = {"ANY"}
            for method in sorted(methods):
                self._append_unique_route(result, path, method, relative, line)

        # Drogon ADD_METHOD_TO(ctrl::handler, "/abs/path", Get, Post)
        for match in DROGON_ADD_METHOD_PATTERN.finditer(content):
            line = line_of(content, match.start())
            for method in _drogon_methods(match.group(2)):
                self._append_unique_route(result, match.group(1) or "/", method, relative, line)

        # Drogon METHOD_ADD(Ctrl::handler, "/rel", Get): path is relative to
        # the controller's /namespace/ClassName path.
        if "METHOD_ADD" in content:
            controllers = _drogon_controller_paths(content)
            for match in DROGON_METHOD_ADD_PATTERN.finditer(content):
                qualifier = match.group(1) or ""
                class_name = qualifier.split("::")[-1] if qualifier else ""
                prefix = controllers.get(class_name)
                if prefix is None:
                    if len(controllers) == 1:
                        prefix = next(iter(controllers.values()))
                    elif qualifier:
                        # Controller declared elsewhere; best effort from the
                        # qualified handler name (ns::Class::fn).
                        prefix = "/" + qualifier.replace("::", "/")
                    else:
                        continue
                path = _join_drogon_path(prefix, match.group(2))
                line = line_of(content, match.start())
                for method in _drogon_methods(match.group(3)):
                    self._append_unique_route(result, path, method, relative, line)

        # Drogon HttpSimpleController PATH_ADD("/abs/path", Get)
        for match in DROGON_PATH_ADD_PATTERN.finditer(content):
            line = line_of(content, match.start())
            for method in _drogon_methods(match.group(2)):
                self._append_unique_route(result, match.group(1) or "/", method, relative, line)

        # cpprestsdk listener URL — the listener is constructed with the full URL
        # which we treat as both an entrypoint and a route (path part).
        for match in CPPRESTSDK_LISTENER_PATTERN.finditer(content):
            url = match.group(1)
            # Best-effort: extract the path component of the URL.
            path_match = re.search(r"https?://[^/]+(/[^?]*)", url)
            if path_match:
                path = path_match.group(1) or "/"
                self._append_unique_route(result, path, "ANY", relative, line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1)
                self._append_unique_secret(
                    result, name, relative,
                    line_of(content, match.start()),
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
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                line_of(content, match.start()),
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
