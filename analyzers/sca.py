"""Resolve static Gradle declarations and check official Maven ranges."""

import json
import re
from collections import defaultdict
from dataclasses import dataclass

from analyzers.common import IDENTIFIER, Kotlin, closing, finding


SEVERITIES = {"low", "medium", "high", "critical"}
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*")
ADVISORY = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}|GHSA-[0-9a-z]{4}(?:-[0-9a-z]{4}){2}")
ALIAS = re.compile(r"[A-Za-z0-9_.-]{1,128}")
PACKAGE = re.compile(r"[\w.-]+:[\w.-]+")
DEPENDENCY_BLOCK = re.compile(r"\bdependencies\s*\{")
CONFIGURATION = r"(?:[A-Za-z_]\w*)?(?:[Ii]mplementation|[Aa]pi|[Cc]ompileOnly|[Rr]untimeOnly|[Aa]nnotationProcessor)|kapt|ksp"
DECLARATION = re.compile(rf"\b(?P<configuration>{CONFIGURATION}|add)\s*\(")
VARIABLE = re.compile(rf"\$(?:\{{({IDENTIFIER})\}}|({IDENTIFIER}))")
PART = r'"([^"\r\n]+)"'
CONSTANT = re.compile(rf'\bval\s+({IDENTIFIER})\s*(?::\s*String\s*)?\s*=\s*(?:{PART}|providers\s*\.\s*gradleProperty\s*\(\s*{PART}\s*\)\s*\.\s*(?:get\s*\(\s*\)|orNull))')
COORDINATE = re.compile(r'\s*(?:(?:enforcedPlatform|platform)\s*\(\s*)?"([\w.-]+):([\w.-]+)(?::([^"\r\n]+))?"')
ADD_CONFIG = re.compile(rf'\s*"({CONFIGURATION})"\s*,')
NAMED = re.compile(rf'\s*(group|name|version)\s*=\s*(?:{PART}|({IDENTIFIER}))\s*(?:,|$)')
LOCK = re.compile(r"([\w.-]+:[\w.-]+):([^=\s]+)=([\w,]+)")
COORDINATE_TAIL = re.compile(r"\s*,?\s*(?:\)\s*,?\s*)?")


def parse_version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value) or len(value) > 80:
        raise ValueError("Ожидается числовая версия")
    parts = tuple(int(item) for item in value.split("."))
    while parts and parts[-1] == 0:
        parts = parts[:-1]
    return parts


@dataclass(frozen=True)
class Interval:
    low: tuple | None
    high: tuple | None
    low_inclusive: bool
    high_inclusive: bool

    def contains(self, version):
        return (self.low is None or version > self.low or (self.low_inclusive and version == self.low)) and (
            self.high is None or version < self.high or (self.high_inclusive and version == self.high)
        )


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: tuple
    severity: str
    intervals: tuple
    fixes: tuple


def interval(raw, official):
    if not isinstance(raw, dict):
        raise ValueError("Некорректный диапазон")
    if official:
        low, high = raw["lower"], raw["upper"]
        low_inclusive, high_inclusive = raw["lowerInclusive"], raw["upperInclusive"]
    else:
        low, high = raw.get("min_inclusive"), raw.get("max_exclusive")
        low_inclusive, high_inclusive = True, False
    if type(low_inclusive) is not bool or type(high_inclusive) is not bool or (low is None and high is None):
        raise ValueError("Некорректные границы диапазона")
    lo = parse_version(low) if low is not None else None
    hi = parse_version(high) if high is not None else None
    if lo is not None and hi is not None and (lo > hi or (lo == hi and not (low_inclusive and high_inclusive))):
        raise ValueError("Пустой диапазон версий")
    return Interval(lo, hi, low_inclusive, high_inclusive)


def load_catalog(path):
    if path is None:
        return None
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    official = isinstance(document, dict)
    entries = document.get("vulnerabilities") if official else document
    if not isinstance(entries, list):
        raise ValueError("Справочник SCA должен содержать массив vulnerabilities или список записей")
    catalog = defaultdict(list)
    for index, entry in enumerate(entries, 1):
        try:
            if official and (not isinstance(entry["group"], str) or not isinstance(entry["artifact"], str)):
                raise ValueError("Некорректные координаты Maven")
            package = f"{entry['group']}:{entry['artifact']}" if official else entry["package"]
            advisory_id = entry["id"] if official else entry["cve"]
            aliases = entry.get("aliases", []) if official else []
            fixes = entry.get("fixedVersions", []) if official else []
            severity = entry["severity"].lower()
            ranges = entry["ranges"]
            if (not PACKAGE.fullmatch(package) or not ADVISORY.fullmatch(advisory_id)
                    or not isinstance(aliases, list) or not all(ALIAS.fullmatch(alias) for alias in aliases)
                    or not isinstance(fixes, list) or not all(isinstance(fix, str) and VERSION.fullmatch(fix) for fix in fixes)
                    or severity not in SEVERITIES or not isinstance(ranges, list) or not ranges):
                raise ValueError("Некорректные поля записи")
            intervals = tuple(interval(item, official) for item in ranges)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError(f"Некорректная запись SCA №{index}") from exc
        catalog[package].append(Advisory(advisory_id, tuple(aliases), severity, intervals, tuple(fixes)))
    return catalog


def read_metadata(directory, name):
    path = directory / name
    if path.is_symlink() or not path.is_file():
        return ""
    try:
        with path.open("rb") as stream:
            content = stream.read(1_000_001)
        return content.decode("utf-8-sig") if len(content) <= 1_000_000 else ""
    except (OSError, UnicodeError):
        return ""


def gradle_properties(root, directory):
    properties = {}
    for folder in dict.fromkeys((root, directory)):
        for line in read_metadata(folder, "gradle.properties").splitlines():
            match = re.fullmatch(r"\s*([\w.-]+)\s*[:=]\s*(.*?)\s*", line)
            if match:
                properties[match[1]] = match[2]
    return properties


def resolved_locks(root, directory):
    locks = defaultdict(list)
    local = read_metadata(directory, "gradle.lockfile")
    for line in (local or read_metadata(root, "gradle.lockfile")).splitlines():
        match = LOCK.fullmatch(line.strip())
        if match:
            locks[match[1]].append((match[2], set(match[3].split(","))))
    return locks


def locked_version(entries, configuration):
    if not entries:
        return None
    runtime = "testRuntimeClasspath" if configuration.lower().startswith("test") else "runtimeClasspath"
    scoped = {version for version, scopes in entries if runtime in scopes or configuration in scopes}
    if len(scoped) == 1:
        return scoped.pop()
    versions = {version for version, _ in entries}
    return versions.pop() if len(versions) == 1 else ""


def declarations(doc):
    for block in DEPENDENCY_BLOCK.finditer(doc.code):
        end = closing(doc.code, block.end() - 1)
        if end is None:
            continue
        for match in DECLARATION.finditer(doc.code, block.end(), end):
            close = closing(doc.code, match.end() - 1)
            if close is None or close > end:
                continue
            offset = match.end()
            configuration = match["configuration"]
            if configuration == "add":
                name = ADD_CONFIG.match(doc.clean, offset, close)
                if not name:
                    continue
                offset = name.end()
                configuration = name[1]
            literal = COORDINATE.match(doc.clean, offset, close)
            if literal and COORDINATE_TAIL.fullmatch(doc.clean, literal.end(), close):
                yield configuration, literal[1], literal[2], literal[3], doc.line(literal.start(1))
                continue
            named = {}
            while part := NAMED.match(doc.clean, offset, close):
                named[part[1]] = part[2] if part[2] is not None else f"${part[3]}"
                offset = part.end()
            if (not doc.clean[offset:close].strip() and {"group", "name"} <= named.keys()
                    and PACKAGE.fullmatch(f"{named['group']}:{named['name']}")):
                yield configuration, named["group"], named["name"], named.get("version"), doc.line(match.start())


def sca_findings(root, path, doc, catalog, skipped):
    properties = gradle_properties(root, path.parent)
    locks = resolved_locks(root, path.parent)
    variables = {match[1]: match[2] or properties.get(match[3], "") for match in CONSTANT.finditer(doc.clean)
                 if doc.code[match.start():match.start(1)].strip()}
    for configuration, group, artifact, declared, line in declarations(doc):
        package = f"{group}:{artifact}"
        version = locked_version(locks.get(package, ()), configuration)
        if version is None:
            version = VARIABLE.sub(lambda ref: variables.get(ref[1] or ref[2], "?"), declared or "")
        try:
            parsed = parse_version(version)
        except ValueError:
            skipped.append({"file": doc.path, "line": line, "package": package})
            continue
        seen = set()
        for advisory in catalog.get(package, ()):
            ids = {advisory.id, *advisory.aliases}
            if ids & seen or not any(item.contains(parsed) for item in advisory.intervals):
                continue
            seen.update(ids)
            cve = next((key for key in (advisory.id, *advisory.aliases)
                        if key.startswith("CVE-") and ADVISORY.fullmatch(key)), None)
            fixed = f" Исправленные версии по справочнику: {', '.join(advisory.fixes)}." if advisory.fixes else ""
            yield finding(
                "sca", "affected-dependency", advisory.severity, doc.path, line,
                "Версия зависимости входит в уязвимый диапазон", "Обновите зависимость до исправленной версии." + fixed,
                group=group, artifact=artifact, version=version, package=package, advisoryId=cve or advisory.id,
                **({"cve": cve} if cve else {}),
            )
