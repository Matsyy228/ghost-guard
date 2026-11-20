"""Shared source and report helpers. No Kotlin code is evaluated."""

import re
from bisect import bisect_right
from dataclasses import dataclass


IDENTIFIER = r"[A-Za-z_]\w*"
STRING = r'"""[\s\S]*?"""|"(?:\\.|[^"\\\r\n])*"'
TOKENS = re.compile(rf"{STRING}|'(?:\\.|[^'\\\r\n])*'|//[^\n]*|/\*")
COMMENT_DELIMITERS = re.compile(r"/\*|\*/")
DECLARATION = re.compile(rf"\bfun\s+({IDENTIFIER})\s*\(")


def mask(source, *, keep_strings=False):
    chunks = []
    offset = 0
    while (match := TOKENS.search(source, offset)) is not None:
        start, end = match.span()
        chunks.append(source[offset:start])
        comment = match[0].startswith("/")
        if match[0] == "/*":
            depth = 1
            end = len(source)
            for marker in COMMENT_DELIMITERS.finditer(source, match.end()):
                depth += 1 if marker[0] == "/*" else -1
                if depth == 0:
                    end = marker.end()
                    break
        token = source[start:end]
        chunks.append(token if keep_strings and not comment else re.sub(r"[^\n]", " ", token))
        offset = end
    chunks.append(source[offset:])
    return "".join(chunks)


def closing(code, start):
    opening = code[start]
    close = {"(": ")", "{": "}", "[": "]"}[opening]
    depth = 1
    for index in range(start + 1, len(code)):
        if code[index] == opening:
            depth += 1
        elif code[index] == close:
            depth -= 1
            if depth == 0:
                return index
    return None


@dataclass(frozen=True)
class Function:
    name: str
    start: int
    parameters: str
    body: int
    end: int


class Kotlin:
    def __init__(self, path, source):
        self.path = path
        self.clean = mask(source, keep_strings=True)
        self.code = mask(source)
        self.starts = [0, *(match.end() for match in re.finditer("\n", source))]

    def line(self, offset):
        return bisect_right(self.starts, offset)

    def functions(self):
        declarations = list(DECLARATION.finditer(self.code))
        for index, match in enumerate(declarations):
            end = declarations[index + 1].start() if index + 1 < len(declarations) else len(self.code)
            close = closing(self.code, match.end() - 1)
            if close is not None and close < end:
                yield Function(match[1], match.start(), self.code[match.end():close], close + 1, end)


def finding(scanner, rule, severity, file, line, title, recommendation, **details):
    return {
        "scanner": scanner, "rule": rule, "severity": severity, "file": file,
        "line": line, "title": title, "recommendation": recommendation, **details,
    }


def submission_report(report):
    findings = []
    for item in report["findings"]:
        category = "SECRET" if item["scanner"] == "secrets" else item["scanner"].upper()
        entry = {
            "category": category, "path": item["file"], "severity": item["severity"].upper(),
            "description": item["title"], "remediation": item["recommendation"],
        }
        if category == "SCA":
            entry.update({name: item[name] for name in ("group", "artifact", "version", "advisoryId")})
        else:
            entry.update({"class": item["rule"], "line": item["line"]})
            if "endLine" in item:
                entry["endLine"] = item["endLine"]
        findings.append(entry)
    return {"findings": findings}
