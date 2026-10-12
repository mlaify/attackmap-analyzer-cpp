"""C++ framework sources and idioms for the shared native sink pass
(AttackMap#189). The language-neutral cases are in test_native_sinks.py."""

from __future__ import annotations

import pytest

from attackmap_analyzer_cpp.native_sinks import find_native_weaknesses


def _hits(code: str, path: str = "src/server.cpp") -> list[tuple[int, str, str, str | None]]:
    return [(w.line, w.kind, w.severity, w.source_kind) for w in find_native_weaknesses(code, path)]


def test_cpp_httplib_handler_lambda() -> None:
    code = (
        "int main() {\n"
        "    httplib::Server svr;\n"
        '    svr.Get("/ping", [](const httplib::Request &req, httplib::Response &res) {\n'
        '        auto host = req.get_param_value("host");\n'
        '        std::string cmd = "ping -c1 " + host;\n'
        "        std::system(cmd.c_str());\n"
        "        char buf[32];\n"
        "        strcpy(buf, req.body.c_str());\n"
        "    });\n"
        '    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) {\n'
        '        std::system("true");\n'
        "    });\n}\n"
    )
    assert _hits(code) == [
        (6, "native_command_exec", "high", "request"),
        (8, "unbounded_copy", "high", "request"),
    ]


def test_crow_drogon_pistache_beast_restbed_requests() -> None:
    code = (
        "#include <pistache/endpoint.h>\n#include <boost/beast/http.hpp>\n#include <restbed>\n"
        'void crow_handler(const crow::request& req) {\n    char b[16];\n    strcpy(b, req.url_params.get("q"));\n}\n'
        "void drogon_handler(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb) {\n"
        '    auto name = req->getParameter("name");\n    printf(name.c_str());\n}\n'
        "void pistache_handler(const Rest::Request& request, Http::ResponseWriter response) {\n"
        "    std::string body = request.body();\n    popen(body.c_str(), \"r\");\n}\n"
        "void beast_handler(http::request<http::string_body>&& req) {\n"
        "    std::string t(req.target());\n    system(t.c_str());\n}\n"
        "void restbed_handler(const std::shared_ptr< Session > session) {\n"
        '    const auto id = session->get_request()->get_path_parameter("id");\n    syslog(LOG_INFO, id.data());\n}\n'
    )
    assert _hits(code) == [
        (6, "unbounded_copy", "high", "request"),
        (10, "format_string", "high", "request"),
        (14, "native_command_exec", "high", "request"),
        (18, "native_command_exec", "high", "request"),
        (22, "format_string", "high", "request"),
    ]


def test_oatpp_endpoint_parameters() -> None:
    code = (
        "class Ctl : public oatpp::web::server::api::ApiController {\n"
        '  ENDPOINT("GET", "/run", run, QUERY(String, cmd), AUTHORIZATION(...)) {\n'
        "    system(cmd->c_str());\n"
        "    return createResponse(Status::CODE_200, \"ok\");\n  }\n};\n"
    )
    assert _hits(code) == [(3, "native_command_exec", "high", "request")]


def test_std_cin_and_new_array() -> None:
    code = (
        "int main() {\n    int n;\n    std::cin >> n;\n    auto *items = new Item[n * 4];\n"
        "    std::string line;\n    std::getline(std::cin, line);\n    printf(line.c_str());\n}\n"
    )
    assert _hits(code) == [(4, "alloc_size_overflow", "medium", "stdin"), (7, "format_string", "medium", "stdin")]


@pytest.mark.parametrize(
    "code",
    [
        # A client building its own Request is not request input.
        'void call() { httplib::Request req; req.path = "/x"; char b[8]; strcpy(b, req.path.c_str()); }',
        # Sized std::string copies and printf with a literal format.
        'void h(const httplib::Request &req) { std::string s = req.body; printf("%s", s.c_str()); }',
        "void h(const httplib::Request &req) { std::vector<char> v; v.resize(req.body.size()); "
        "memcpy(v.data(), req.body.data(), req.body.size()); }",
        # Raw string literals are masked.
        'void f() { const char *s = R"(system(argv[1]); gets(b);)"; }',
        # Methods named like sinks are not libc calls.
        "void f(Obj &o, const char *x) { o.system(x); logger.printf(x); }",
    ],
)
def test_cpp_negatives(code: str) -> None:
    assert _hits(code) == []


def test_cpp_non_bounding_and_sizing_idioms() -> None:
    code = (
        "void h(const httplib::Request &req) {\n"
        "    char buf[64];\n"
        "    int n = static_cast<int>(req.body.size());\n"
        "    std::vector<char> tmp(n);\n"
        "    memcpy(buf, req.body.data(), n);\n}\n"
    )
    assert _hits(code) == [(5, "tainted_copy_length", "high", "request")]


def test_constants_followed_through_c_str() -> None:
    code = 'void f() {\n    std::string cmd = "uptime";\n    std::system(cmd.c_str());\n    printf(cmd.c_str());\n}\n'
    assert _hits(code) == []


def test_arrow_getters_need_a_framework_request_receiver() -> None:
    code = (
        "void f(Config *cfg, Message *msg) {\n    char b[8];\n"
        '    strcpy(b, cfg->getPath().c_str());\n    system(msg->getBody().c_str());\n}\n'
        "void g(const HttpRequestPtr &req) {\n    system(req->getParameter(\"x\").c_str());\n}\n"
    )
    assert _hits(code) == [(4, "native_command_exec", "low", None), (7, "native_command_exec", "high", "request")]


def test_bare_request_type_needs_its_framework() -> None:
    code = "void h(const Request &req) {\n    system(req.body.c_str());\n}\n"
    assert _hits(code) == [(2, "native_command_exec", "low", None)]
    assert _hits("#include <httplib.h>\n" + code) == [(3, "native_command_exec", "high", "request")]
