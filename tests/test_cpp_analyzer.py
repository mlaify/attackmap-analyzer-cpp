"""Tests for the CppAnalyzer plugin."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attackmap_analyzer_cpp import CppAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_cpp(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    assert CppAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_hpp(tmp_path: Path) -> None:
    (tmp_path / "api.hpp").write_text("#pragma once\nclass Foo {};\n", encoding="utf-8")
    assert CppAnalyzer().detect(tmp_path) is True


def test_detect_skips_build_dir(tmp_path: Path) -> None:
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "stale.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    assert CppAnalyzer().detect(tmp_path) is False


def test_detect_does_not_claim_pure_c_repo(tmp_path: Path) -> None:
    """A repo with only `.c` and `.h` files belongs to the C analyzer."""
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    assert CppAnalyzer().detect(tmp_path) is False


# ---------- Crow ----------


def test_crow_route_default_method(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <crow.h>\n'
        '\n'
        'int main() {\n'
        '    crow::SimpleApp app;\n'
        '    CROW_ROUTE(app, "/health")([](){ return "ok"; });\n'
        '    app.port(8080).run();\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/health", "ANY") in pairs


def test_crow_route_with_methods_chain(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <crow.h>\n'
        'crow::SimpleApp app;\n'
        'CROW_ROUTE(app, "/users").methods("GET"_method, "POST"_method)\n'
        '    ([](const crow::request& r){ return "ok"; });\n'
        'CROW_ROUTE(app, "/admin").methods("DELETE"_method)\n'
        '    ([](){ return "deleted"; });\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/users", "GET") in pairs
    assert ("/users", "POST") in pairs
    assert ("/admin", "DELETE") in pairs


# ---------- Pistache ----------


def test_pistache_routes(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <pistache/router.h>\n'
        '\n'
        'using namespace Pistache;\n'
        '\n'
        'void setup(Rest::Router& router) {\n'
        '    Rest::Routes::Get(router, "/api/users", Rest::Routes::bind(&handle_users));\n'
        '    Rest::Routes::Post(router, "/api/login", Rest::Routes::bind(&handle_login));\n'
        '    Rest::Routes::Delete(router, "/api/users/:id", Rest::Routes::bind(&handle_delete));\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/users", "GET") in pairs
    assert ("/api/login", "POST") in pairs
    assert ("/api/users/:id", "DELETE") in pairs


# ---------- Drogon ----------


def test_drogon_register_handler_with_methods(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <drogon/drogon.h>\n'
        '\n'
        'int main() {\n'
        '    drogon::app().registerHandler(\n'
        '        "/api/orders",\n'
        '        [](const drogon::HttpRequestPtr& req, std::function<void(...)>&& cb) {},\n'
        '        {Drogon::Get, Drogon::Post});\n'
        '    drogon::app().run();\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/orders", "GET") in pairs
    assert ("/api/orders", "POST") in pairs


def test_drogon_add_method_to_macro(tmp_path: Path) -> None:
    (tmp_path / "controller.hpp").write_text(
        '#pragma once\n'
        '#include <drogon/HttpController.h>\n'
        '\n'
        'class Users : public drogon::HttpController<Users> {\n'
        'public:\n'
        '    METHOD_LIST_BEGIN\n'
        '    ADD_METHOD_TO(Users::list, "/users", Get);\n'
        '    ADD_METHOD_TO(Users::create, "/users", Post);\n'
        '    METHOD_LIST_END\n'
        '\n'
        '    void list(...);\n'
        '    void create(...);\n'
        '};\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/users", "GET") in pairs
    assert ("/users", "POST") in pairs


# ---------- cpprestsdk ----------


def test_cpprestsdk_listener_extracts_url_path(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <cpprest/http_listener.h>\n'
        '\n'
        'using namespace web::http::experimental::listener;\n'
        '\n'
        'int main() {\n'
        '    http_listener listener("https://0.0.0.0:443/api/v1");\n'
        '    listener.support(web::http::methods::GET, [](auto req){});\n'
        '    listener.open().wait();\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    paths = {r.path for r in result.routes}
    assert "/api/v1" in paths


# ---------- HTTP clients ----------


def test_libcurl_url_extracted(tmp_path: Path) -> None:
    (tmp_path / "client.cpp").write_text(
        '#include <curl/curl.h>\n'
        'void fetch() {\n'
        '    CURL *curl = curl_easy_init();\n'
        '    curl_easy_setopt(curl, CURLOPT_URL, "https://api.stripe.com/v1/charges");\n'
        '    curl_easy_perform(curl);\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


def test_cpr_url_extracted(tmp_path: Path) -> None:
    (tmp_path / "client.cpp").write_text(
        '#include <cpr/cpr.h>\n'
        'void fetch() {\n'
        '    auto resp = cpr::Get(cpr::Url{"https://api.example.com/data"});\n'
        '    auto post = cpr::Post(cpr::Url{"https://api.example.com/submit"}, cpr::Body{"x"});\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.example.com/data" in targets
    assert "https://api.example.com/submit" in targets


def test_cpprestsdk_http_client_url(tmp_path: Path) -> None:
    (tmp_path / "client.cpp").write_text(
        '#include <cpprest/http_client.h>\n'
        'using web::http::client::http_client;\n'
        'void fetch() {\n'
        '    http_client client(U("https://api.example.com/v2"));\n'
        '    client.request(web::http::methods::GET);\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.example.com/v2" in targets


# ---------- Databases ----------


def test_libpqxx_connection_emits_postgresql(tmp_path: Path) -> None:
    (tmp_path / "db.cpp").write_text(
        '#include <pqxx/pqxx>\n'
        'void connect() {\n'
        '    pqxx::connection c{"postgresql://localhost/app"};\n'
        '    pqxx::work tx{c};\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


def test_mongocxx_redispp_each_emit_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "mongo.cpp").write_text(
        '#include <mongocxx/client.hpp>\n'
        'void x() {\n'
        '    mongocxx::client client{mongocxx::uri{"mongodb://x"}};\n'
        '}\n',
        encoding="utf-8",
    )
    (tmp_path / "redis.cpp").write_text(
        '#include <sw/redis++/redis++.h>\n'
        'void x() {\n'
        '    sw::redis::Redis redis("tcp://127.0.0.1:6379");\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "mongodb" in kinds
    assert "redis" in kinds


def test_mysqlx_session_emits_mysql(tmp_path: Path) -> None:
    (tmp_path / "db.cpp").write_text(
        '#include <mysqlx/xdevapi.h>\n'
        'void connect() {\n'
        '    mysqlx::Session s{mysqlx::SessionSettings("mysqlx://localhost")};\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert any(d.kind == "mysql" for d in result.databases)


# ---------- Auth ----------


def test_jwt_cpp_emits_jwt_hint(tmp_path: Path) -> None:
    (tmp_path / "auth.cpp").write_text(
        '#include <jwt-cpp/jwt.h>\n'
        'std::string sign(const std::string& secret) {\n'
        '    return jwt::create()\n'
        '        .set_issuer("svc")\n'
        '        .sign(jwt::algorithm::hs256{secret});\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert any(h.hint == "jwt" for h in result.auth_hints)


def test_libsodium_argon2_high_confidence(tmp_path: Path) -> None:
    (tmp_path / "auth.cpp").write_text(
        '#include <sodium.h>\n'
        'int hash(const char *pw, char *out) {\n'
        '    return crypto_pwhash_str(out, pw, strlen(pw),\n'
        '        crypto_pwhash_OPSLIMIT_INTERACTIVE,\n'
        '        crypto_pwhash_MEMLIMIT_INTERACTIVE);\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "argon2" in by_hint
    assert by_hint["argon2"].confidence == 0.9


def test_botan_tls_server(tmp_path: Path) -> None:
    (tmp_path / "tls.cpp").write_text(
        '#include <botan/tls_server.h>\n'
        'class MyServer : public Botan::TLS::Server {};\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert any(h.hint == "botan" for h in result.auth_hints)


def test_cryptopp_aes_emits_hint(tmp_path: Path) -> None:
    (tmp_path / "crypto.cpp").write_text(
        '#include <cryptopp/aes.h>\n'
        'CryptoPP::AES::Encryption enc;\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert any(h.hint == "cryptopp" for h in result.auth_hints)


# ---------- Secrets ----------


def test_std_getenv_secrets(tmp_path: Path) -> None:
    (tmp_path / "config.cpp").write_text(
        '#include <cstdlib>\n'
        '#include <string>\n'
        '\n'
        'std::string load() {\n'
        '    const char *jwt = std::getenv("JWT_SECRET");\n'
        '    const char *db = std::getenv("DATABASE_PASSWORD");\n'
        '    return jwt ? jwt : "";\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names


def test_getenv_with_non_secret_name_skipped(tmp_path: Path) -> None:
    (tmp_path / "config.cpp").write_text(
        'const char *home = std::getenv("HOME");\n'
        'const char *path = getenv("PATH");\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert result.secret_hints == []


# ---------- Frameworks + entrypoints ----------


def test_crow_app_run_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <crow.h>\n'
        'int main() {\n'
        '    crow::SimpleApp app;\n'
        '    CROW_ROUTE(app, "/")([](){ return "hi"; });\n'
        '    app.port(8080).multithreaded().run();\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "crow" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "crow_app_run" in ep


def test_drogon_app_run_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <drogon/drogon.h>\n'
        'int main() { drogon::app().run(); }\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "drogon" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "drogon_run" in ep


def test_cpprestsdk_listener_open_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include <cpprest/http_listener.h>\n'
        'using namespace web::http::experimental::listener;\n'
        'int main() {\n'
        '    http_listener listener("http://0.0.0.0:80/api");\n'
        '    listener.open().wait();\n'
        '}\n',
        encoding="utf-8",
    )
    result = CppAnalyzer().analyze(tmp_path)
    ep = {e.hint for e in result.entrypoint_hints}
    assert "cpprestsdk_listener_open" in ep


# ---------- CMake → service hint ----------


def test_cmake_project_picked_up(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        'project(billing-cpp LANGUAGES CXX)\n', encoding="utf-8"
    )
    (tmp_path / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    result = CppAnalyzer().analyze(tmp_path)
    assert any(h.hint == "project:billing-cpp" for h in result.service_hints)


# ---------- End-to-end ----------


def test_full_drogon_service_signal_set(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        'project(orders-cpp LANGUAGES CXX)\nadd_executable(orders main.cpp)\n',
        encoding="utf-8",
    )
    (tmp_path / "main.cpp").write_text(
        '#include <drogon/drogon.h>\n'
        '#include <pqxx/pqxx>\n'
        '#include <jwt-cpp/jwt.h>\n'
        '#include <openssl/ssl.h>\n'
        '#include <cpr/cpr.h>\n'
        '#include <cstdlib>\n'
        '\n'
        'int main() {\n'
        '    const char *secret = std::getenv("JWT_SECRET");\n'
        '    pqxx::connection conn{"postgresql://localhost/orders"};\n'
        '    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());\n'
        '    auto resp = cpr::Get(cpr::Url{"https://api.stripe.com/v1/charges"});\n'
        '\n'
        '    drogon::app().registerHandler("/api/orders", handler, {Drogon::Get, Drogon::Post});\n'
        '    drogon::app().registerHandler("/admin/refund", refund, {Drogon::Post});\n'
        '    drogon::app().run();\n'
        '}\n',
        encoding="utf-8",
    )

    result = CppAnalyzer().analyze(tmp_path)

    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/api/orders", "GET") in pairs
    assert ("/api/orders", "POST") in pairs
    assert ("/admin/refund", "POST") in pairs

    assert any(d.kind == "postgresql" for d in result.databases)
    assert any(h.hint == "jwt" for h in result.auth_hints)
    assert any(h.hint == "openssl_tls" for h in result.auth_hints)
    assert any(s.name == "JWT_SECRET" for s in result.secret_hints)
    assert any(e.target == "https://api.stripe.com/v1/charges" for e in result.external_calls)
    assert any(f.hint == "drogon" for f in result.framework_hints)
    assert any(e.hint == "drogon_run" for e in result.entrypoint_hints)
    assert any(h.hint == "project:orders-cpp" for h in result.service_hints)


# ---------- Repo walking (AttackMap#253) ----------

_WALK_FIXTURE = (
    '#include <crow.h>\n'
    '#include <cstdlib>\n'
    'int main() {\n'
    '    const char *jwt = std::getenv("JWT_SECRET");\n'
    '    crow::SimpleApp app;\n'
    '    CROW_ROUTE(app, "/login")([](){ return "hi"; });\n'
    '    app.port(8080).multithreaded().run();\n'
    '}\n'
)


def test_repo_under_skip_dir_named_parents_is_analyzed(tmp_path: Path) -> None:
    """A checkout under /.../build/out/... must not be skipped (absolute-path bug)."""
    repo = tmp_path / "build" / "out" / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.cpp").write_text(_WALK_FIXTURE, encoding="utf-8")
    analyzer = CppAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == 1
    assert any(r.path == "/login" for r in result.routes)
    assert any(s.name == "JWT_SECRET" and s.file == "src/main.cpp" for s in result.secret_hints)


def test_skip_dirs_inside_repo_still_skipped(tmp_path: Path) -> None:
    for skipped in ("build", "third_party", "Release"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "dep.cpp").write_text(_WALK_FIXTURE, encoding="utf-8")
    assert CppAnalyzer().detect(tmp_path) is False
    result = CppAnalyzer().analyze(tmp_path)
    assert result.files_scanned == 0
    assert result.routes == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_source_outside_repo_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.cpp").write_text('auto k = std::getenv("OUTSIDE_SECRET_KEY");\n', encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (repo / "linked.cpp").symlink_to(outside / "secret.cpp")
    result = CppAnalyzer().analyze(repo)
    assert result.files_scanned == 1
    assert result.secret_hints == []


def test_cp1252_source_is_analyzed(tmp_path: Path) -> None:
    (tmp_path / "legacy.cpp").write_bytes(
        (
            '// Gestion des accès — café\n'
            '#include <cstdlib>\n'
            'auto pw = std::getenv("DB_PASSWORD");\n'
        ).encode("cp1252")
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert result.files_scanned == 1
    secret = next(s for s in result.secret_hints if s.name == "DB_PASSWORD")
    assert secret.line == 3


def test_experimental_analyzer_is_opt_in() -> None:
    assert CppAnalyzer.metadata.experimental is True
    assert CppAnalyzer.metadata.enabled_by_default is False


# ---------- mlaify/attackmap-analyzer-c#2: .h ownership, Drogon METHOD_ADD / PATH_ADD ----------

_DROGON_CONTROLLER_H = """#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

namespace api
{
namespace v1
{
class User : public drogon::HttpController<User>
{
  public:
    METHOD_LIST_BEGIN
    METHOD_ADD(User::getInfo, "/{id}", Get);
    ADD_METHOD_TO(User::login, "/api/v1/login", Post);
    METHOD_LIST_END
};
}  // namespace v1
}  // namespace api
"""


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _routes(result) -> set[tuple[str, str, str]]:
    return {(r.method, r.path, r.file) for r in result.routes}


@pytest.mark.parametrize(
    "extra",
    [
        {"controllers/api_v1_User.cc": '#include "api_v1_User.h"\n'},
        {"CMakeLists.txt": "project(app CXX)\n"},
    ],
    ids=["with-cc-source", "header-only-cmake-cxx"],
)
def test_drogon_header_controller_yields_both_routes(tmp_path: Path, extra: dict[str, str]) -> None:
    _write_tree(tmp_path, {"controllers/api_v1_User.h": _DROGON_CONTROLLER_H, **extra})
    analyzer = CppAnalyzer()
    assert analyzer.detect(tmp_path) is True
    result = analyzer.analyze(tmp_path)
    assert _routes(result) == {
        ("GET", "/api/v1/User/{id}", "controllers/api_v1_User.h"),
        ("POST", "/api/v1/login", "controllers/api_v1_User.h"),
    }
    assert result.languages == ["cpp"]
    assert any(f.hint == "drogon" and f.file == "controllers/api_v1_User.h" for f in result.framework_hints)


def test_detect_does_not_claim_bridging_header_or_pure_c_headers(tmp_path: Path) -> None:
    _write_tree(
        tmp_path,
        {
            "App/App-Bridging-Header.h": '#import "MyLib.h"\n',
            "App/AppDelegate.swift": "import UIKit\n",
            "lib/CMakeLists.txt": "project(lib C)\n",
            "lib/util.h": "int util(void);\n",
        },
    )
    assert CppAnalyzer().detect(tmp_path) is False


def test_drogon_method_add_variants(tmp_path: Path) -> None:
    _write_tree(
        tmp_path,
        {
            "Items.h": (
                "#include <drogon/HttpController.h>\n"
                "namespace shop::v2 {\n"
                "class Items final : public drogon::HttpController<Items> {\n"
                "  public:\n"
                "    METHOD_LIST_BEGIN\n"
                '    METHOD_ADD(Items::list, "", Get);\n'
                '    METHOD_ADD(Items::update, "/{id}", Put, Patch, "AuthFilter");\n'
                '    METHOD_ADD(Items::any, "/any/{1}");\n'
                '    ADD_METHOD_TO(Items::bulk, "/bulk", drogon::Post, drogon::Options);\n'
                "    METHOD_LIST_END\n"
                "};\n"
                "}\n"
            ),
            "Health.h": (
                "#include <drogon/HttpController.h>\n"
                "class Health : public drogon::HttpController<Health> {\n"
                "    METHOD_LIST_BEGIN\n"
                '    METHOD_ADD(Health::ping, "/ping", Get);\n'
                "    METHOD_LIST_END\n"
                "};\n"
            ),
            "Root.h": (
                "#include <drogon/HttpSimpleController.h>\n"
                "class Root : public drogon::HttpSimpleController<Root> {\n"
                "  public:\n"
                "    PATH_LIST_BEGIN\n"
                '    PATH_ADD("/", Get, Post);\n'
                '    PATH_ADD("/status", "LoginFilter");\n'
                "    PATH_LIST_END\n"
                "};\n"
            ),
            "main.cc": "int main() {}\n",
        },
    )
    assert _routes(CppAnalyzer().analyze(tmp_path)) == {
        ("GET", "/shop/v2/Items", "Items.h"),
        ("PUT", "/shop/v2/Items/{id}", "Items.h"),
        ("PATCH", "/shop/v2/Items/{id}", "Items.h"),
        ("ANY", "/shop/v2/Items/any/{1}", "Items.h"),
        ("POST", "/bulk", "Items.h"),
        ("OPTIONS", "/bulk", "Items.h"),
        ("GET", "/Health/ping", "Health.h"),
        ("GET", "/", "Root.h"),
        ("POST", "/", "Root.h"),
        ("ANY", "/status", "Root.h"),
    }


def test_detect_performs_a_single_walk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    files: dict[str, str] = {}
    for i in range(20):
        files[f"mod{i}/CMakeLists.txt"] = f"project(mod{i} C)\n"
        files[f"mod{i}/Makefile"] = "all:\n"
        files[f"mod{i}/inc/x{i}.h"] = "int x(void);\n"
    _write_tree(tmp_path, files)

    walks: list[object] = []
    real_walk = os.walk

    def counting_walk(*args, **kwargs):
        walks.append(args[0] if args else kwargs.get("top"))
        return real_walk(*args, **kwargs)

    rglobs: list[str] = []
    real_rglob = Path.rglob

    def counting_rglob(self, pattern, *args, **kwargs):
        rglobs.append(pattern)
        return real_rglob(self, pattern, *args, **kwargs)

    monkeypatch.setattr(os, "walk", counting_walk)
    monkeypatch.setattr(Path, "rglob", counting_rglob)

    assert CppAnalyzer().detect(tmp_path) is False
    assert len(walks) == 1
    assert rglobs == []


# The .h ownership rule, mirrored case-for-case in attackmap-analyzer-c's
# tests: (files besides a.c + inc/api.h, owner of inc/api.h).
_OWNERSHIP_CASES = [
    ({}, "c"),
    ({"CMakeLists.txt": "project(lib C)\n"}, "c"),
    ({"CMakeLists.txt": "project(lib)\n"}, "c"),
    ({"CMakeLists.txt": "cmake_minimum_required(VERSION 3.10)\nproject(lib VERSION 1.0 LANGUAGES CXX)\n"}, "cpp"),
    ({"CMakeLists.txt": "PROJECT(lib C CXX)\n"}, "cpp"),
    ({"CMakeLists.txt": "project(lib C)\nenable_language(CXX)\n"}, "cpp"),
    ({"CMakeLists.txt": "project(lib C)\nset(CMAKE_CXX_STANDARD 17)\n"}, "cpp"),
    ({"sub/CMakeLists.txt": "project(sub CXX)\n"}, "cpp"),
    ({"src/server.cpp": "int main() {}\n"}, "cpp"),
    ({"src/server.cc": "int main() {}\n"}, "cpp"),
    ({"src/server.cxx": "int main() {}\n"}, "cpp"),
    ({"inc/util.hpp": "#pragma once\n"}, "cpp"),
    # Pruned by one of the two plugins: never a marker for either.
    ({"build/gen.cpp": "int g() {}\n"}, "c"),
    ({"third_party/lib/x.cc": "int x() {}\n"}, "c"),
    ({"Release/gen.cpp": "int g() {}\n"}, "c"),
    ({"Debug/CMakeLists.txt": "project(dbg CXX)\n"}, "c"),
]


@pytest.mark.parametrize(("extra", "owner"), _OWNERSHIP_CASES)
def test_header_ownership_rule(tmp_path: Path, extra: dict[str, str], owner: str) -> None:
    _write_tree(
        tmp_path,
        {
            "a.c": '#include "inc/api.h"\nint main(void) { return 0; }\n',
            "inc/api.h": '#pragma once\nstatic const char *k(void) { return getenv("API_TOKEN"); }\n',
            **extra,
        },
    )
    analyzer = CppAnalyzer()
    result = analyzer.analyze(tmp_path)
    scanned_header = any(s.file == "inc/api.h" and s.name == "API_TOKEN" for s in result.secret_hints)
    assert scanned_header is (owner == "cpp")
    assert analyzer.detect(tmp_path) is (owner == "cpp")
