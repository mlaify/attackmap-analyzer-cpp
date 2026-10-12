"""cpp-httplib, oat++ and restbed routes (AttackMap#191)."""

from __future__ import annotations

import random
from pathlib import Path

from attackmap_analyzer_cpp import CppAnalyzer
from attackmap_analyzer_cpp.framework_routes import framework_routes


def _routes(code: str) -> list[tuple[str, str, int | None, str]]:
    return [(r.method, r.path, r.line, r.auth) for r in framework_routes(code, "src/app.cpp")]


# ---------- cpp-httplib ----------


def test_httplib_server_routes() -> None:
    code = (
        '#include "httplib.h"\n'
        "int main() {\n"
        "    httplib::Server svr;\n"
        '    svr.Get("/hi", [](const httplib::Request &, httplib::Response &res) {});\n'
        '    svr.Post("/items", handler);\n'
        '    svr.Delete(R"(/items/(\\d+))", handler);\n'
        '    svr.Get("/numbers/(\\\\d+)", handler);\n'
        "}\n"
    )
    assert _routes(code) == [
        ("GET", "/hi", 4, "unknown"),
        ("POST", "/items", 5, "unknown"),
        ("DELETE", r"/items/(\d+)", 6, "unknown"),
        ("GET", r"/numbers/(\d+)", 7, "unknown"),
    ]


def test_httplib_ssl_and_pointer_servers() -> None:
    code = (
        "using namespace httplib;\n"
        'SSLServer https("cert.pem", "key.pem");\n'
        "std::unique_ptr<httplib::Server> api = std::make_unique<httplib::Server>();\n"
        'void setup() { https.Put("/a", h); api->Patch("/b", h); }\n'
    )
    assert [(m, p) for m, p, _, _ in _routes(code)] == [("PUT", "/a"), ("PATCH", "/b")]


def test_httplib_client_calls_are_not_routes() -> None:
    code = (
        "#include <httplib.h>\n"
        'int main() {\n    httplib::Client cli("localhost", 8080);\n'
        '    auto res = cli.Get("/hi");\n    cli.Post("/post", body, "text/plain");\n}\n'
    )
    assert _routes(code) == []


def test_client_next_to_a_server_is_not_a_route() -> None:
    code = (
        '#include "httplib.h"\nint main() {\n    httplib::Server svr;\n    svr.Post("/post", h);\n'
        '    httplib::Client cli("localhost", 1234);\n    auto res = cli.Post("/post", body, "application/json");\n}\n'
    )
    assert _routes(code) == [("POST", "/post", 4, "unknown")]


def test_get_on_unrelated_types_is_ignored() -> None:
    code = 'Config cfg;\nvoid f() { cfg.Get("/path"); }\n'
    assert _routes(code) == []


# ---------- oat++ ----------


def test_oatpp_endpoints_and_authorization() -> None:
    code = (
        "class UserController : public oatpp::web::server::api::ApiController {\n"
        '  ENDPOINT_INFO(getUser) { info->summary = "x"; }\n'
        '  ENDPOINT("GET", "users/{userId}", getUser, PATH(Int32, userId)) {\n'
        "    return createResponse(Status::CODE_200);\n  }\n"
        '  ENDPOINT("DELETE", "/users/{userId}", deleteUser,\n'
        "           PATH(Int32, userId),\n"
        "           AUTHORIZATION(std::shared_ptr<oatpp::web::server::handler::DefaultBasicAuthorizationObject>, auth)) {\n"
        "    return createResponse(Status::CODE_200);\n  }\n"
        '  ENDPOINT_ASYNC("POST", "/upload", Upload) {};\n'
        "};\n"
    )
    assert _routes(code) == [
        ("GET", "/users/{userId}", 3, "unknown"),
        ("DELETE", "/users/{userId}", 6, "required"),
        ("POST", "/upload", 11, "unknown"),
    ]
    guarded = framework_routes(code, "c.hpp")[1]
    assert guarded.guards == ["AUTHORIZATION"]
    assert guarded.guard_evidence is not None and "AUTHORIZATION" in guarded.guard_evidence


def test_oatpp_macro_definition_is_not_a_route() -> None:
    assert _routes("#define ENDPOINT(METHOD, PATH, NAME, ...) OATPP_MACRO_API_CONTROLLER_ENDPOINT(...)\n") == []


# ---------- restbed ----------


RESTBED = (
    "#include <restbed>\nusing namespace restbed;\n"
    "int main() {\n"
    "    auto resource = make_shared< Resource >( );\n"
    '    resource->set_path( "/resource" );\n'
    '    resource->set_method_handler( "GET", get_handler );\n'
    '    resource->set_method_handler( "POST", post_handler );\n'
    "    auto multi = make_shared< Resource >( );\n"
    '    multi->set_paths( { "/a", "b/{id: [0-9]+}" } );\n'
    "    Service service;\n    service.publish( resource );\n    service.publish( multi );\n"
)


def test_restbed_resources() -> None:
    assert _routes(RESTBED + "}\n") == [
        ("GET", "/resource", 5, "unknown"),
        ("POST", "/resource", 5, "unknown"),
        ("ANY", "/a", 9, "unknown"),
        ("ANY", "/b/{id: [0-9]+}", 9, "unknown"),
    ]


def test_restbed_authentication_handlers() -> None:
    per_resource = RESTBED.replace(
        '    resource->set_method_handler( "GET", get_handler );\n',
        '    resource->set_method_handler( "GET", get_handler );\n    resource->set_authentication_handler( auth );\n',
    )
    assert [(p, a) for _, p, _, a in _routes(per_resource + "}\n")] == [
        ("/resource", "required"),
        ("/resource", "required"),
        ("/a", "unknown"),
        ("/b/{id: [0-9]+}", "unknown"),
    ]
    service_wide = RESTBED + "    service.set_authentication_handler( auth );\n}\n"
    assert {a for _, _, _, a in _routes(service_wide)} == {"required"}
    route = framework_routes(service_wide, "x.cpp")[0]
    assert route.guards == ["set_authentication_handler"]


def test_restbed_client_request_set_path_is_not_a_route() -> None:
    code = '#include <restbed>\nvoid f() {\n    auto request = make_shared< Request >( );\n    request->set_path( "/x" );\n}\n'
    assert _routes(code) == []


# ---------- integration + robustness ----------


def test_analyzer_emits_framework_routes_and_hints(tmp_path: Path) -> None:
    (tmp_path / "main.cpp").write_text(
        '#include "httplib.h"\nint main() { httplib::Server svr; svr.Get("/hi", h); }\n', encoding="utf-8"
    )
    result = CppAnalyzer().analyze(tmp_path)
    assert [(r.path, r.method) for r in result.routes] == [("/hi", "GET")]
    assert "cpp-httplib" in {h.hint for h in result.framework_hints}


def test_fuzz_never_raises() -> None:
    rng = random.Random(191)
    pieces = ['svr.Get("', "ENDPOINT(", "AUTHORIZATION(", "->set_path(", "set_paths({", 'R"(', ")", "(", '"', "{", "}",
              "httplib::Server svr;", "make_shared< Resource >", "\n", "x", "/"]
    for _ in range(500):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 80)))
        framework_routes(text, "f.cpp")
    framework_routes('ENDPOINT("GET", "/x", n' + "(" * 50000, "f.cpp")
