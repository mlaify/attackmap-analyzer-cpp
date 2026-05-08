"""Tests for the CppAnalyzer plugin."""

from __future__ import annotations

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
