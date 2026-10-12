"""Route extraction for cpp-httplib, oat++ and restbed (AttackMap#191).

- **cpp-httplib**: ``svr.Get("/x", ...)`` / ``Post`` / ``Put`` / ``Patch`` /
  ``Delete`` / ``Options`` on a receiver declared in the same file as a
  ``httplib::Server`` or ``SSLServer`` (a ``httplib::Client`` uses the same
  method names, so an undeclared receiver is skipped). Regex paths
  (``R"(/numbers/(\\d+))"``) are kept as written.
- **oat++**: ``ENDPOINT("GET", "users/{id}", name, ...)`` and
  ``ENDPOINT_ASYNC``. An ``AUTHORIZATION(...)`` parameter sets
  ``Route.auth = "required"``. Paths get a leading ``/``. A router-level
  prefix isn't visible in the controller and isn't applied.
- **restbed**: ``resource->set_path("/x")`` / ``set_paths({...})`` on a
  ``Resource`` variable, joined with
  that resource's ``set_method_handler("GET", ...)`` calls (``ANY`` when it
  has none). ``set_authentication_handler`` on the resource, or on a service
  in the same file, sets ``auth = "required"``.

Every scanner is bounded; patterns are module-level and linear.
"""

from __future__ import annotations

import re

from attackmap.sdk import line_of

from .contracts import Route

_MAX_ARGS_SPAN = 2000

# ---------- cpp-httplib ----------

_HTTPLIB_FILE_RE = re.compile(r"\bhttplib\b")
_HTTPLIB_SERVER_DECL_RE = re.compile(
    r"\b(?:httplib::)?(?:SSL)?Server\b\s*(?:[*&]\s*)?([A-Za-z_]\w*)\s*[;({=,)]"
    r"|\b(?:std::)?(?:unique_ptr|shared_ptr)\s*<\s*(?:httplib::)?(?:SSL)?Server\s*>\s*([A-Za-z_]\w*)"
)
_HTTPLIB_ROUTE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:\.|->)\s*(Get|Post|Put|Patch|Delete|Options)\s*\(\s*"
    r"(?:R\"(?P<delim>[^()\\\s\"]{0,16})\((?P<raw>[^\n]{0,300}?)\)(?P=delim)\"|\"(?P<plain>(?:[^\"\\\n]|\\.){0,300})\")"
)

# ---------- oat++ ----------

_OATPP_ENDPOINT_RE = re.compile(r"\bENDPOINT(?:_ASYNC)?\s*\(\s*\"([A-Za-z]+)\"\s*,\s*\"([^\"\n]*)\"")
_OATPP_AUTH_RE = re.compile(r"\bAUTHORIZATION\s*\(")

# ---------- restbed ----------

_RESTBED_FILE_RE = re.compile(r"\brestbed\b|<\s*Resource\s*>")
# A Resource variable: `auto r = make_shared< Resource >()`, `Resource r;`,
# `shared_ptr< Resource > r`. A client `Request` also has set_path().
_RESTBED_RESOURCE_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:std::)?make_shared\s*<\s*(?:restbed::)?Resource\s*>"
    r"|(?:\bshared_ptr\s*<\s*(?:restbed::)?Resource\s*>|(?<![\w:<])(?:restbed::)?Resource)\s*[&*]?\s*([A-Za-z_]\w*)\s*[;=({,)]"
)
_RESTBED_SET_PATH_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*set_path\s*\(\s*\"([^\"\n]*)\"\s*\)")
_RESTBED_SET_PATHS_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*set_paths\s*\(")
_STRING_LITERAL_RE = re.compile(r"\"([^\"\n]*)\"")
_RESTBED_METHOD_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*set_method_handler\s*\(\s*\"([A-Za-z]+)\"")
_RESTBED_AUTH_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*set_authentication_handler\s*\(")


def _paren_args(content: str, open_paren: int) -> str | None:
    depth = 0
    for i in range(open_paren, min(len(content), open_paren + _MAX_ARGS_SPAN)):
        c = content[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return content[open_paren + 1 : i]
    return None


def _rooted(path: str) -> str:
    """oat++ and restbed resolve paths against the root: `users` is `/users`."""
    return path if path.startswith("/") else "/" + path


def _snippet(content: str, offset: int) -> str:
    start = content.rfind("\n", 0, offset) + 1
    end = content.find("\n", offset)
    return content[start : end if end != -1 else len(content)].strip()[:160]


def httplib_routes(content: str, relative: str) -> list[Route]:
    if _HTTPLIB_FILE_RE.search(content) is None:
        return []
    servers = {m.group(1) or m.group(2) for m in _HTTPLIB_SERVER_DECL_RE.finditer(content)}
    servers.discard(None)
    if not servers:
        return []
    routes: list[Route] = []
    for match in _HTTPLIB_ROUTE_RE.finditer(content):
        if match.group(1) not in servers:
            continue
        raw = match.group("raw")
        path = raw if raw is not None else match.group("plain").replace("\\\\", "\\")
        routes.append(Route(path=path, method=match.group(2).upper(), file=relative, line=line_of(content, match.start())))
    return routes


def oatpp_routes(content: str, relative: str) -> list[Route]:
    routes: list[Route] = []
    for match in _OATPP_ENDPOINT_RE.finditer(content):
        path = _rooted(match.group(2))
        open_paren = content.index("(", match.start())
        args = _paren_args(content, open_paren) or ""
        auth = _OATPP_AUTH_RE.search(args)
        route = Route(path=path, method=match.group(1).upper(), file=relative, line=line_of(content, match.start()))
        if auth is not None:
            route.auth = "required"
            route.guards = ["AUTHORIZATION"]
            route.guard_evidence = _snippet(content, open_paren + 1 + auth.start())
        routes.append(route)
    return routes


def restbed_routes(content: str, relative: str) -> list[Route]:
    if _RESTBED_FILE_RE.search(content) is None:
        return []
    resources = {m.group(1) or m.group(2) for m in _RESTBED_RESOURCE_DECL_RE.finditer(content)}
    paths: dict[str, list[tuple[str, int]]] = {}
    for match in _RESTBED_SET_PATH_RE.finditer(content):
        if match.group(1) in resources:
            paths.setdefault(match.group(1), []).append((_rooted(match.group(2)), match.start()))
    for match in _RESTBED_SET_PATHS_RE.finditer(content):
        if match.group(1) in resources:
            for literal in _STRING_LITERAL_RE.finditer(_paren_args(content, match.end() - 1) or ""):
                paths.setdefault(match.group(1), []).append((_rooted(literal.group(1)), match.start()))
    if not paths:
        return []
    methods: dict[str, list[str]] = {}
    for match in _RESTBED_METHOD_RE.finditer(content):
        methods.setdefault(match.group(1), []).append(match.group(2).upper())
    auth_resources: dict[str, int] = {}
    service_auth: int | None = None
    for match in _RESTBED_AUTH_RE.finditer(content):
        if match.group(1) in paths:
            auth_resources.setdefault(match.group(1), match.start())
        elif service_auth is None:
            service_auth = match.start()
    routes: list[Route] = []
    for resource, declared in paths.items():
        guard_at = auth_resources.get(resource, service_auth)
        for path, offset in declared:
            for method in sorted(set(methods.get(resource, ["ANY"]))):
                route = Route(path=path, method=method, file=relative, line=line_of(content, offset))
                if guard_at is not None:
                    route.auth = "required"
                    route.guards = ["set_authentication_handler"]
                    route.guard_evidence = _snippet(content, guard_at)
                routes.append(route)
    return routes


def framework_routes(content: str, relative: str) -> list[Route]:
    """Routes from cpp-httplib, oat++ and restbed registrations in one file."""
    return [*httplib_routes(content, relative), *oatpp_routes(content, relative), *restbed_routes(content, relative)]


__all__ = ["framework_routes", "httplib_routes", "oatpp_routes", "restbed_routes"]
