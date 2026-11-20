"""Conservative Kotlin/Spring source rules for inputs, security and ownership."""

import re
from collections import defaultdict

from analyzers.common import IDENTIFIER, STRING, closing, finding


JDBC = re.compile(r"\b(?:JdbcTemplate|NamedParameterJdbcTemplate|JdbcClient)\b")
QUERY = re.compile(r"\.\s*(?:query(?:ForList|ForObject|ForMap)?|sql|update|execute)\s*\(")
SQL = re.compile(r"\b(?:select|insert|update|delete|with)\b", re.I)
BIND_REQUEST = re.compile(rf"@(?:RequestParam|PathVariable|RequestHeader)(?:\s*\([^)]*\))?\s+({IDENTIFIER})\s*:")
PATH_VARIABLE = re.compile(rf"@PathVariable(?:\s*\([^)]*\))?\s+({IDENTIFIER})\s*:")
VARIABLE = re.compile(rf"\$(?:\{{\s*({IDENTIFIER})\b|({IDENTIFIER}))")
QUERY_LITERAL = re.compile(rf"\s*({STRING})")
SQL_ARGUMENT = re.compile(rf"\s*({IDENTIFIER})\s*(?=[,)])")
TLS_OVERRIDE = re.compile(
    r"\b(?:hostnameVerifier\s*=|setHostnameVerifier\s*\()\s*(?:(?:[\w.]+\.)?HostnameVerifier\s*)?"
    r"\{\s*(?:[\w\s,:?]{1,80}->\s*)?(?:return(?:@\w+)?\s+)?true\s*;?\s*\}"
    r"|\b(?:hostnameVerifier\s*=|setHostnameVerifier\s*\()\s*(?:[\w.]+\.)?NoopHostnameVerifier\s*\.\s*INSTANCE\b"
)
CORS_WILDCARD = re.compile(
    rf'(?:(?P<receiver>{IDENTIFIER})\s*\.\s*)?\b(?:allowedOrigins|allowedOriginPatterns)\s*=\s*(?:listOf|mutableListOf|setOf)\s*\('
    rf'|(?:(?P<setter>{IDENTIFIER})\s*\.\s*)?\baddAllowedOrigin(?:Pattern)?\s*\('
)
WILDCARD_ARGUMENT = re.compile(r'(?:^|,)\s*"\*"\s*(?=,|$)')
CORS_CREDENTIALS = re.compile(
    rf"(?:(?P<receiver>{IDENTIFIER})\s*\.\s*)?\ballowCredentials\s*=\s*true\b"
    rf"|(?:(?P<setter>{IDENTIFIER})\s*\.\s*)?\bsetAllowCredentials\s*\(\s*true\s*\)"
)
CORS_BLOCK = re.compile(r"\bCorsConfiguration\s*\(\s*\)\s*\.\s*(?:apply|also)\s*\{")
ROUTE = re.compile(r"\b(?:requestMatchers|antMatchers|mvcMatchers)\s*\(")
ACCESS = re.compile(r"\s*\.\s*(permitAll|authenticated|hasAnyRole|hasRole|hasAuthority|hasAnyAuthority|access|denyAll)\s*\(")
STRING_PATH = re.compile(r'"(/[^"\r\n]*)"')
HTTP_METHOD = re.compile(r"^\s*(?:HttpMethod\s*\.\s*)?(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*,")
CLASS = re.compile(rf"\bclass\s+({IDENTIFIER})\b")
TYPED_RECEIVER = re.compile(rf"\b(?:val|var)\s+({IDENTIFIER})\s*:\s*({IDENTIFIER})\b")
METHOD_CALL = re.compile(rf"\b({IDENTIFIER})\s*\.\s*({IDENTIFIER})\s*\(\s*({IDENTIFIER})\s*,?\s*\)")
OWNER = r"(?:owner|customer|user|account|tenant|principal|member)_?id"
OWNER_COLUMN = re.compile(rf"\b{OWNER}\b", re.I)
ROW_ID = re.compile(r"\b(?:\w+_)?id\s*=\s*(?:\?|:\w+\b)", re.I)
SELECT = re.compile(r"\bselect\s+(.*?)\s+from\s+.+?\s+where\s+(.+)", re.I | re.S)
AUTH_CHECK = re.compile(r"\b(?:Principal|Authentication|SecurityContextHolder|PreAuthorize|PostAuthorize|hasPermission|checkOwnership|requireOwnership|authorizeOwnership)\b", re.I)


def issue(doc, code, severity, start, end, title, fix):
    line, last = doc.line(start), doc.line(end)
    locations = {"endLine": last} if 0 < last - line <= 14 else {}
    return finding("sast", code, severity, doc.path, line, title, fix, **locations)


def first_query_argument(doc, call, function):
    literal = QUERY_LITERAL.match(doc.clean, call.end(), function.end)
    if literal:
        return literal[1], literal.start(1)
    variable = SQL_ARGUMENT.match(doc.clean, call.end(), function.end)
    if variable:
        name = re.escape(variable[1])
        assignment = re.compile(rf"\bval\s+{name}\s*(?::\s*String\s*)?=\s*({STRING})")
        values = [m for m in assignment.finditer(doc.clean, function.body, call.start())
                  if doc.code[m.start():m.start(1)].strip()]
        if values:
            return values[-1][1], values[-1].start(1)
    return "", call.start()


def sql_checks(doc):
    if not JDBC.search(doc.code):
        return
    for function in doc.functions():
        names = set(BIND_REQUEST.findall(function.parameters))
        if not names:
            continue
        for call in QUERY.finditer(doc.code, function.body, function.end):
            value, offset = first_query_argument(doc, call, function)
            references = {match[1] or match[2] for match in VARIABLE.finditer(value)}
            if SQL.search(value) and references & names:
                start = function.start if doc.line(offset) - doc.line(function.start) <= 14 else offset
                yield issue(
                    doc, "sql-injection", "high", start, max(call.start(), offset),
                    "Параметр запроса подставляется в SQL-шаблон", "Передавайте параметры в JDBC отдельно от текста SQL.",
                )


def cors_checks(doc):
    if not re.search(r"\bCorsConfiguration\b", doc.code):
        return
    blocks = [(match.end(), closing(doc.code, match.end() - 1)) for match in CORS_BLOCK.finditer(doc.code)]
    for function in doc.functions():
        credentials = list(CORS_CREDENTIALS.finditer(doc.code, function.body, function.end))
        for wildcard in CORS_WILDCARD.finditer(doc.code, function.body, function.end):
            end = closing(doc.code, wildcard.end() - 1)
            if end is None or end >= function.end or not WILDCARD_ARGUMENT.search(doc.clean[wildcard.end():end]):
                continue
            receiver = wildcard["receiver"] or wildcard["setter"]
            for allow in credentials:
                allow_receiver = allow["receiver"] or allow["setter"]
                if receiver and receiver != allow_receiver:
                    continue
                if not receiver and (allow_receiver or not any(
                    end is not None and start <= wildcard.start() < end and start <= allow.start() < end for start, end in blocks
                )):
                    continue
                yield issue(doc, "credentialed-cors", "medium", min(wildcard.start(), allow.start()),
                            max(wildcard.start(), allow.start()), "CORS разрешает любой origin вместе с учётными данными",
                            "Укажите доверенные origin и включайте credentials только для нужных маршрутов.")
                break


def route_checks(doc):
    if not re.search(r"\b(?:HttpSecurity|SecurityFilterChain)\b", doc.code):
        return
    for function in doc.functions():
        routes = []
        for call in ROUTE.finditer(doc.code, function.body, function.end):
            end = closing(doc.code, call.end() - 1)
            if end is None or end >= function.end:
                continue
            access = ACCESS.match(doc.code, end + 1, function.end)
            if access:
                method = HTTP_METHOD.match(doc.code, call.end(), end)
                for path in STRING_PATH.finditer(doc.clean, call.end(), end):
                    routes.append((call.start(), path[1], method[1] if method else None, access[1]))
        for index, (offset, path, method, access) in enumerate(routes):
            if access != "permitAll" or "*" in path or "{" in path:
                continue
            for _, pattern, guarded_method, policy in routes[index + 1:]:
                if policy == "permitAll" or (method and guarded_method and method != guarded_method):
                    continue
                prefix = pattern[:-2] if pattern.endswith("/**") else ""
                if path == pattern or (len(prefix) > 1 and "*" not in prefix and path.startswith(prefix)):
                    yield issue(doc, "route-authorization", "high", offset, offset,
                                "Публичное правило срабатывает раньше ограничения доступа к маршруту",
                                "Согласуйте порядок правил Spring Security с политикой доступа и проверьте роль на маршруте.")
                    break


def unauthorized_readers(documents):
    readers = defaultdict(list)
    for doc in documents:
        if not JDBC.search(doc.code):
            continue
        names = CLASS.findall(doc.code)
        for function in doc.functions():
            if AUTH_CHECK.search(doc.code, function.start, function.end):
                continue
            for call in QUERY.finditer(doc.code, function.body, function.end):
                value, offset = first_query_argument(doc, call, function)
                sql = SELECT.search(value)
                if (sql and OWNER_COLUMN.search(sql[1]) and ROW_ID.search(sql[2])
                        and not OWNER_COLUMN.search(sql[2]) and not re.search(r"\sor\s", sql[2], re.I)):
                    for name in names:
                        readers[name, function.name].append((doc, function.start, offset))
    return readers


def object_checks(documents):
    readers = unauthorized_readers(documents)
    seen = set()
    for doc in documents:
        if not re.search(r"@(?:RestController|Controller)\b", doc.code):
            continue
        receivers = dict(TYPED_RECEIVER.findall(doc.code))
        for function in doc.functions():
            parameters = set(PATH_VARIABLE.findall(function.parameters))
            if not parameters or AUTH_CHECK.search(doc.code, function.start, function.end):
                continue
            for call in METHOD_CALL.finditer(doc.code, function.body, function.end):
                if call[3] not in parameters:
                    continue
                for reader, start, end in readers.get((receivers.get(call[1]), call[2]), ()):
                    key = (reader.path, start)
                    if key not in seen:
                        seen.add(key)
                        yield issue(reader, "object-authorization", "high", start, end,
                                    "Идентификатор из маршрута читает запись без проверки её владельца",
                                    "Фильтруйте запись по идентификатору и владельцу из контекста аутентификации.")


def kotlin_sast(documents):
    for doc in documents:
        yield from sql_checks(doc)
        yield from cors_checks(doc)
        yield from route_checks(doc)
        for match in TLS_OVERRIDE.finditer(doc.code):
            yield issue(doc, "tls-verification", "medium", match.start(), match.end() - 1,
                        "Клиент принимает любое имя TLS-хоста", "Оставьте штатную проверку имени хоста при TLS-соединении.")
    yield from object_checks(documents)
