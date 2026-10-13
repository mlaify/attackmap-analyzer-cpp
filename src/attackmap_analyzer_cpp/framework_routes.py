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

# ---------- masking ----------

_MASK_START_RE = re.compile(r"(?P<line>//)|(?P<block>/\*)|(?P<raw>(?<![\w])(?:u8|[uUL])?R\"(?P<delim>[^()\\\s\"]{0,16})\()|(?P<str>\")|(?P<chr>')")
_STRING_BODY_RE = re.compile(r"(?:[^\"\\\n]|\\[\s\S])*")
_CHAR_BODY_RE = re.compile(r"(?:[^'\\\n]|\\[\s\S]){0,8}'")


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _masks(text: str) -> tuple[str, str]:
    """``(code, bare)``: ``code`` has comments blanked (literals kept, for the
    paths); ``bare`` also has literal contents blanked, to tell whether a
    match starts inside a string. One linear pass; same length as ``text``."""
    code: list[str] = []
    bare: list[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        match = _MASK_START_RE.search(text, pos)
        if match is None:
            break
        start = match.start()
        code.append(text[pos:start])
        bare.append(text[pos:start])
        if match.group("line") is not None:
            newline = text.find("\n", start)
            end = n if newline == -1 else newline
            code.append(_blank(text[start:end]))
            bare.append(_blank(text[start:end]))
        elif match.group("block") is not None:
            close = text.find("*/", match.end())
            end = n if close == -1 else close + 2
            code.append(_blank(text[start:end]))
            bare.append(_blank(text[start:end]))
        else:
            if match.group("raw") is not None:
                terminator = ")" + match.group("delim") + '"'
                close = text.find(terminator, match.end())
                end = n if close == -1 else close + len(terminator)
            elif match.group("str") is not None:
                body = _STRING_BODY_RE.match(text, match.end())
                end = body.end() if body else match.end()
                if end < n and text[end] == '"':
                    end += 1
            else:
                body = _CHAR_BODY_RE.match(text, match.end())
                end = body.end() if body else match.end()
            code.append(text[start:end])
            bare.append(text[start : match.end()] + _blank(text[match.end() : end]))
        pos = end
    code.append(text[pos:])
    bare.append(text[pos:])
    return "".join(code), "".join(bare)


def _in_code(code: str, bare: str, offset: int) -> bool:
    """The match at ``offset`` starts in code, not inside a string literal."""
    return offset < len(bare) and bare[offset] == code[offset]

# ---------- cpp-httplib ----------

_HTTPLIB_FILE_RE = re.compile(r"\bhttplib\b")
_HTTPLIB_SERVER_DECL_RE = re.compile(
    r"\b(?:httplib::)?(?:SSL)?Server\b\s*(?:[*&]\s*)?([A-Za-z_]\w*)\s*[;({=,)]"
    r"|\b(?:std::)?(?:unique_ptr|shared_ptr)\s*<\s*(?:httplib::)?(?:SSL)?Server\s*>\s*([A-Za-z_]\w*)"
    r"|\b([A-Za-z_]\w*)\s*=\s*(?:std::)?make_(?:unique|shared)\s*<\s*(?:httplib::)?(?:SSL)?Server\s*>"
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
_RESTBED_SERVICE_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:std::)?make_shared\s*<\s*(?:restbed::)?Service\s*>"
    r"|(?:\bshared_ptr\s*<\s*(?:restbed::)?Service\s*>|(?<![\w:<])(?:restbed::)?Service)\s*[&*]?\s*([A-Za-z_]\w*)\s*[;=({,)]"
)
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


def httplib_routes(content: str, relative: str, masks: tuple[str, str] | None = None) -> list[Route]:
    code, bare = masks or _masks(content)
    if _HTTPLIB_FILE_RE.search(content) is None:
        return []
    servers = {
        m.group(1) or m.group(2) or m.group(3)
        for m in _HTTPLIB_SERVER_DECL_RE.finditer(bare)
    }
    servers.discard(None)
    if not servers:
        return []
    routes: list[Route] = []
    for match in _HTTPLIB_ROUTE_RE.finditer(code):
        if match.group(1) not in servers or not _in_code(code, bare, match.start()):
            continue
        raw = match.group("raw")
        path = raw if raw is not None else match.group("plain").replace("\\\\", "\\")
        routes.append(Route(path=path, method=match.group(2).upper(), file=relative, line=line_of(content, match.start())))
    return routes


def oatpp_routes(content: str, relative: str, masks: tuple[str, str] | None = None) -> list[Route]:
    code, bare = masks or _masks(content)
    routes: list[Route] = []
    for match in _OATPP_ENDPOINT_RE.finditer(code):
        if not _in_code(code, bare, match.start()):
            continue
        path = _rooted(match.group(2))
        open_paren = code.index("(", match.start())
        args = _paren_args(bare, open_paren) or ""
        auth = _OATPP_AUTH_RE.search(args)
        route = Route(path=path, method=match.group(1).upper(), file=relative, line=line_of(content, match.start()))
        if auth is not None:
            route.auth = "required"
            route.guards = ["AUTHORIZATION"]
            route.guard_evidence = _snippet(content, open_paren + 1 + auth.start())
        routes.append(route)
    return routes


def restbed_routes(content: str, relative: str, masks: tuple[str, str] | None = None) -> list[Route]:
    code, bare = masks or _masks(content)
    if _RESTBED_FILE_RE.search(bare) is None:
        return []
    resources = {m.group(1) or m.group(2) for m in _RESTBED_RESOURCE_DECL_RE.finditer(bare)}
    services = {m.group(1) or m.group(2) for m in _RESTBED_SERVICE_DECL_RE.finditer(bare)}
    paths: dict[str, list[tuple[str, int]]] = {}
    for match in _RESTBED_SET_PATH_RE.finditer(code):
        if match.group(1) in resources and _in_code(code, bare, match.start()):
            paths.setdefault(match.group(1), []).append((_rooted(match.group(2)), match.start()))
    for match in _RESTBED_SET_PATHS_RE.finditer(code):
        if match.group(1) in resources and _in_code(code, bare, match.start()):
            for literal in _STRING_LITERAL_RE.finditer(_paren_args(code, match.end() - 1) or ""):
                paths.setdefault(match.group(1), []).append((_rooted(literal.group(1)), match.start()))
    if not paths:
        return []
    methods: dict[str, list[str]] = {}
    for match in _RESTBED_METHOD_RE.finditer(code):
        if _in_code(code, bare, match.start()):
            methods.setdefault(match.group(1), []).append(match.group(2).upper())
    # A handler on a Resource guards that resource only (even one whose path
    # isn't a literal); on a Service, every resource in the file; on an
    # unknown receiver, nothing (ambiguous: auth stays unknown).
    auth_resources: dict[str, int] = {}
    service_auth: int | None = None
    for match in _RESTBED_AUTH_RE.finditer(bare):
        receiver = match.group(1)
        if receiver in resources:
            auth_resources.setdefault(receiver, match.start())
        elif receiver in services and service_auth is None:
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
    """Routes from cpp-httplib, oat++ and restbed registrations in one file.
    Commented-out code and text inside string literals don't count."""
    if not _FRAMEWORK_HINT_RE.search(content):
        return []
    masks = _masks(content)
    return [
        *httplib_routes(content, relative, masks),
        *oatpp_routes(content, relative, masks),
        *restbed_routes(content, relative, masks),
    ]


_FRAMEWORK_HINT_RE = re.compile(r"\bhttplib\b|\bENDPOINT|\bset_paths?\b")


__all__ = ["framework_routes", "httplib_routes", "oatpp_routes", "restbed_routes"]
