"""Find embedded credentials by role and usage, without exporting their values."""

import re

from analyzers.common import IDENTIFIER, STRING, finding


KEY = re.compile(r"(?:api|access|private)[_.-]?key", re.I)
PASSWORD = re.compile(r"pass(?:word|wd|phrase)", re.I)
TOKEN = re.compile(r"token|secret|credential", re.I)
METADATA = re.compile(r"(?:endpoint|url|uri|path|header|name|length|ttl|enabled|required|format|variable|env)$", re.I)
PLACEHOLDER = re.compile(r"\$\{|^\$|^<[^>]+>$|^\{[^}]+\}$|^(?:true|false|null|changeme|example|placeholder|redacted|dummy|replace[-_ ]?me|your[-_ ].+|\*+)$", re.I)
CONFIG_DEFAULT = re.compile(r"\$\{([\w.-]+):([^{}]+)\}")
BEARER = re.compile(r"^Bearer\s+(.+)$", re.I)
DECLARATION = re.compile(rf"\b(?:val|var)\s+({IDENTIFIER})\s*(?::\s*String\??\s*)?=\s*")
LITERAL = re.compile(STRING)
ENVIRONMENT = re.compile(rf'\bSystem\s*\.\s*getenv\s*\(\s*"([\w.-]+)"\s*\)\s*\?:\s*({STRING})')
ATOM = re.compile(rf"(?:{STRING})|{IDENTIFIER}")
BEARER_SETTER = re.compile(r"\.\s*setBearerAuth\s*\(|\bsetBearerAuth\s*\(")
PARTS_SEPARATOR = re.compile(r"\s*\+\s*")


def role(name):
    if METADATA.search(name):
        return None
    if PASSWORD.search(name):
        return "password"
    if KEY.search(name):
        return "api-key"
    if TOKEN.search(name):
        return "configuration-token"
    return None


def literal_value(token):
    return token[3:-3] if token.startswith('"""') else token[1:-1]


def is_literal_secret(value):
    return bool(value.strip()) and not PLACEHOLDER.search(value.strip())


def secret(path, line, kind, severity, end_line=None):
    titles = {
        "password": "Пароль задан строковым литералом",
        "api-key": "Ключ API задан строковым литералом",
        "configuration-token": "Токен задан строковым литералом",
        "secret-fallback": "Секрет хранится как значение по умолчанию",
        "recoverable-token": "Токен для заголовка собирается из литералов",
    }
    details = {"endLine": end_line} if end_line is not None and 0 < end_line - line <= 14 else {}
    return finding(
        "secrets", kind, severity, path, line, titles[kind],
        "Передавайте секрет из окружения или хранилища, удалите литерал и замените действующий секрет.",
        **details,
    )


def config_secrets(path, entries):
    for number, key, value in entries:
        name = key.rsplit(".", 1)[-1]
        if name.lower() == "key":
            name = ".".join(key.rsplit(".", 2)[-2:])
        kind = role(name)
        bearer = BEARER.fullmatch(value)
        if name.lower() == "authorization" and bearer:
            kind, value = "configuration-token", bearer[1]
        default = CONFIG_DEFAULT.fullmatch(value)
        if default and (kind or role(default[1])) and is_literal_secret(default[2]):
            yield secret(path, number, "secret-fallback", "high" if kind == "password" else "medium")
        elif kind and is_literal_secret(value):
            yield secret(path, number, kind, "medium" if kind == "api-key" else "high")


def constant_parts(expression, known):
    used = []
    offset = 0
    for _ in range(24):
        match = ATOM.match(expression, offset)
        if not match:
            return None
        atom = match[0]
        if atom.startswith('"'):
            value = literal_value(atom)
            if not is_literal_secret(value) or "$" in value:
                return None
            used.append((len(value), (), 1))
        elif atom in known:
            used.append(known[atom])
        else:
            return None
        gap = PARTS_SEPARATOR.match(expression, match.end())
        if not gap:
            if expression[match.end():].strip():
                return None
            first = min((line for part in used for line in part[1]), default=None)
            return min(1024, sum(part[0] for part in used)), (first,) if first else (), min(2, sum(part[2] for part in used))
        offset = gap.end()
    return None


def composed_secrets(doc):
    for function in doc.functions():
        constants = {}
        initially_reported = set()
        pattern = re.compile(rf"{DECLARATION.pattern}|{BEARER_SETTER.pattern}")
        for match in pattern.finditer(doc.code, function.body, function.end):
            # The masked form consumes string spaces after '=', so find the same prefix in clean text.
            if match[1]:
                declaration = DECLARATION.match(doc.clean, match.start())
                if declaration is None:
                    continue
                end = doc.clean.find("\n", declaration.end(), function.end)
                end = function.end if end < 0 else end
                expression = doc.clean[declaration.end():end].split(";", 1)[0].strip()
                parts = constant_parts(expression, constants)
                constants.pop(match[1], None)
                if parts:
                    constants[match[1]] = (parts[0], parts[1] or (doc.line(match.start()),), parts[2])
                continue
            suffix = re.match(r"([^()\r\n]{1,512})\)", doc.clean[match.end():function.end])
            parts = constant_parts(suffix[1].strip(), constants) if suffix else None
            if parts and parts[0] >= 8 and parts[2] > 1:
                first = min(parts[1], default=doc.line(match.start()))
                end = doc.line(match.start())
                location = (first, end)
                if location not in initially_reported:
                    initially_reported.add(location)
                    yield secret(doc.path, first if end - first <= 14 else end, "recoverable-token", "medium", end)


def kotlin_secrets(doc):
    for match in DECLARATION.finditer(doc.clean):
        if not doc.code[match.start():match.start(1)].strip():
            continue
        kind = role(match[1])
        value = LITERAL.match(doc.clean, match.end())
        if (kind and value and is_literal_secret(literal_value(value[0]))
                and not doc.clean[value.end():].lstrip().startswith("+")):
            yield secret(doc.path, doc.line(value.start()), kind, "medium" if kind == "api-key" else "high")
    for match in ENVIRONMENT.finditer(doc.clean):
        if not doc.code[match.start():match.start() + len("System")].strip():
            continue
        kind = role(match[1])
        if kind and is_literal_secret(literal_value(match[2])):
            severity = "high" if kind == "password" else "low" if re.search(r"status|health|readonly|read_only", match[1], re.I) else "medium"
            yield secret(doc.path, doc.line(match.start(2)), "secret-fallback", severity)
    yield from composed_secrets(doc)
