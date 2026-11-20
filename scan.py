"""Local defensive checks for Kotlin/Spring Boot training projects."""

import argparse
import json
import os
import re
from collections import defaultdict
from pathlib import Path


SEVERITIES = {"low", "medium", "high", "critical"}
SCANNERS = frozenset({"secrets", "sca", "sast"})
SKIP_DIRS = {".git", ".gradle", ".idea", "build", "out"}
MAX_FILE_SIZE = 1_000_000
SECRET_NAME = re.compile(
    r"password|passwd|(?:api|access|private)[_.-]?key|token|secret", re.I
)
METADATA_SUFFIX = re.compile(r"(?:endpoint|url|uri|path|header|name|length|ttl|enabled)$", re.I)
PLACEHOLDER = re.compile(
    r"\$\{|^\$|^<[^>]+>$|^\{[^}]+\}$|^(?:true|false|null|changeme|example|placeholder|redacted)$",
    re.I,
)
CONFIG_VALUE = re.compile(r"^([\w.-]+)\s*[:=]\s*(.*?)\s*$")
KOTLIN_VALUE = re.compile(
    r'\b([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"([^"\r\n]*)"'
)
GRADLE_CONFIGURATION = (
    r"(?:[A-Za-z_]\w*)?(?:[Ii]mplementation|[Aa]pi|[Cc]ompileOnly|"
    r"[Rr]untimeOnly|[Aa]nnotationProcessor)|kapt|ksp"
)
GRADLE_COORDINATE = re.compile(
    rf'\b(?:{GRADLE_CONFIGURATION})\s*\(\s*(?:(?:enforcedPlatform|platform)\s*\(\s*)?'
    r'"([\w.-]+):([\w.-]+):([^"\r\n]+)"'
)
GRADLE_NAMED = re.compile(
    rf'\b(?:{GRADLE_CONFIGURATION})\s*\(\s*group\s*=\s*"([\w.-]+)"\s*,\s*'
    r'name\s*=\s*"([\w.-]+)"\s*,\s*version\s*=\s*"([^"\r\n]+)"'
)
VERSION_REF = re.compile(r"^\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))$")
NUMERIC_VERSION = re.compile(r"\d+(?:\.\d+)*", re.ASCII)
CSRF_DISABLED = re.compile(
    r"\.\s*csrf\s*(?:\(\s*\)\s*\.\s*disable\s*\(\s*\)|"
    r"(?:\(\s*)?\{\s*(?:(?:\w+\s*->\s*)?\w+\s*\.\s*)?disable\s*\(\s*\)\s*\})"
)
KOTLIN_TOKEN = re.compile(
    r'"""[\s\S]*?"""|"(?:\\.|[^"\\\r\n])*"|'
    r"'(?:\\.|[^'\\\r\n])*'|//[^\n]*|/\*[\s\S]*?\*/"
)


def finding(scanner, rule, severity, file, line, title, recommendation, **details):
    return {
        "scanner": scanner, "rule": rule, "severity": severity, "file": file,
        "line": line, "title": title, "recommendation": recommendation, **details,
    }


def config_entries(path, source):
    parents = []
    is_yaml = path.endswith((".yaml", ".yml"))
    for number, line in enumerate(source.splitlines(), 1):
        match = CONFIG_VALUE.fullmatch(line.lstrip())
        if not match:
            continue
        key, value = match.groups()
        if value[:1] in {'"', "'"} and value.count(value[0]) >= 2:
            value = value.split(value[0], 2)[1]
        elif is_yaml:
            value = re.split(r"(?:^|\s)#", value, maxsplit=1)[0].strip()
        if is_yaml:
            depth = len(line) - len(line.lstrip())
            while parents and parents[-1][0] >= depth:
                parents.pop()
            if not value:
                parents.append((depth, key))
                continue
            key = ".".join([parent for _, parent in parents] + [key])
        yield number, key, value


def secret_findings(path, entries):
    for number, key, value in entries:
        name = key.rsplit(".", 1)[-1]
        if name.lower() == "key":
            name = ".".join(key.rsplit(".", 2)[-2:])
        if SECRET_NAME.search(name) and not METADATA_SUFFIX.search(name) and value and not PLACEHOLDER.search(value):
            yield finding(
                "secrets", "hardcoded-secret", "high", path, number,
                "Вероятный секрет в исходниках или конфигурации",
                "Уберите значение в менеджер секретов или переменную окружения и замените действующий секрет.",
            )


def masked_kotlin(source, *, keep_strings=False):
    def replace(match):
        token = match[0]
        if keep_strings and not token.startswith("/"):
            return token
        return re.sub(r"[^\n]", " ", token)

    return KOTLIN_TOKEN.sub(replace, source)


def kotlin_secrets(source):
    masked = masked_kotlin(source)
    for match in KOTLIN_VALUE.finditer(masked_kotlin(source, keep_strings=True)):
        if masked[match.start():match.start(1) + len(match[1])].strip():
            yield source.count("\n", 0, match.start(1)) + 1, match[1], match[2]


def sast_findings(path, source, config):
    if path.endswith(".kt"):
        for match in CSRF_DISABLED.finditer(masked_kotlin(source)):
            yield finding(
                "sast", "spring-csrf-disabled", "medium", path,
                source.count("\n", 0, match.start()) + 1,
                "Отключена защита от CSRF",
                "Проверьте способ аутентификации. Включите защиту для запросов с браузерными сессиями.",
            )

    for number, key, value in config:
        if key == "management.endpoints.web.exposure.include" and any(
            endpoint.strip() == "*" for endpoint in value.split(",")
        ):
            yield finding(
                "sast", "actuator-expose-all", "medium", path, number,
                "Открыты все веб-эндпоинты Spring Boot Actuator",
                "Перечислите только нужные эндпоинты и ограничьте доступ к диагностике.",
            )
        if key == "server.error.include-stacktrace" and value.lower() == "always":
            yield finding(
                "sast", "spring-stacktrace-exposed", "medium", path, number,
                "Трассировка стека всегда включена в ответы об ошибках",
                "Отключите трассировку в HTTP-ответах и оставьте её во внутренних логах.",
            )


def parse_version(value):
    if not isinstance(value, str) or not NUMERIC_VERSION.fullmatch(value):
        raise ValueError("Версия должна состоять из числовых компонентов, разделённых точками")
    parts = tuple(int(part) for part in value.split("."))
    while parts and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def load_catalog(path):
    if path is None:
        return None
    entries = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(entries, list):
        raise ValueError("Справочник SCA должен содержать массив записей")
    catalog = defaultdict(list)
    for index, entry in enumerate(entries, 1):
        try:
            package = entry["package"]
            cve = entry["cve"]
            severity = entry["severity"]
            intervals = [(parse_version(item["min_inclusive"]) if "min_inclusive" in item else None,
                          parse_version(item["max_exclusive"]) if "max_exclusive" in item else None)
                         for item in entry["ranges"]]
            if not (re.fullmatch(r"[\w.-]+:[\w.-]+", package)
                    and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve)
                    and severity in SEVERITIES and intervals
                    and all((lo is not None or hi is not None) and
                            (lo is None or hi is None or lo < hi) for lo, hi in intervals)):
                raise ValueError("Некорректный пакет, CVE, уровень риска или диапазон")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Некорректная запись SCA №{index}: {exc}") from exc
        catalog[package].append((cve, severity, intervals))
    return catalog


def sca_findings(path, source, catalog, skipped):
    gradle = masked_kotlin(source, keep_strings=True)
    base = masked_kotlin(source)
    variables = {match[1]: match[2] for match in KOTLIN_VALUE.finditer(gradle)
                 if base[match.start(1):match.end(1)].strip()}
    for pattern in (GRADLE_COORDINATE, GRADLE_NAMED):
        for match in pattern.finditer(gradle):
            if not base[match.start():match.start(1)].strip():
                continue
            group, artifact, version = match.groups()
            reference = VERSION_REF.fullmatch(version)
            if reference:
                version = variables.get(reference[1] or reference[2], "")
            line = source.count("\n", 0, match.start(1)) + 1
            try:
                parsed = parse_version(version)
            except ValueError:
                skipped.append({"file": path, "line": line, "package": f"{group}:{artifact}"})
                continue
            package = f"{group}:{artifact}"
            for cve, severity, intervals in catalog.get(package, ()):
                if any((lo is None or lo <= parsed) and (hi is None or parsed < hi)
                       for lo, hi in intervals):
                    yield finding(
                        "sca", "affected-dependency", severity, path, line,
                        "Версия зависимости попадает в диапазон из справочника",
                        "Обновите зависимость до версии за пределами уязвимого диапазона.",
                        package=package, version=version, cve=cve,
                    )


def project_files(root):
    for folder, dirs, files in os.walk(root):
        directory = Path(folder)
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS
                         and not (directory / name).is_symlink()
                         and not (directory / name).is_junction())
        for name in sorted(files):
            path = directory / name
            if path.suffix in {".kt", ".kts", ".yaml", ".yml", ".properties"} and not path.is_symlink():
                yield path


def scan(root, catalog=None, *, scanners=SCANNERS):
    findings = []
    skipped_files = []
    unresolved_versions = []
    for path in project_files(root):
        relative = path.relative_to(root).as_posix()
        if scanners == {"sca"} and path.name != "build.gradle.kts":
            continue
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_FILE_SIZE + 1)
            if len(data) > MAX_FILE_SIZE:
                skipped_files.append({"file": relative, "reason": "size"})
                continue
            source = data.decode("utf-8-sig")
        except (OSError, UnicodeError):
            skipped_files.append({"file": relative, "reason": "read"})
            continue

        config = [] if path.suffix in {".kt", ".kts"} else list(config_entries(relative, source))
        secrets = kotlin_secrets(source) if path.suffix in {".kt", ".kts"} else config
        if "secrets" in scanners:
            findings.extend(secret_findings(relative, secrets))
        if "sast" in scanners:
            findings.extend(sast_findings(relative, source, config))
        if "sca" in scanners and path.name == "build.gradle.kts" and catalog is not None:
            findings.extend(sca_findings(relative, source, catalog, unresolved_versions))

    findings.sort(key=lambda item: (item["file"], item["line"], item["rule"], item.get("cve", "")))
    for index, item in enumerate(findings, 1):
        item["id"] = f"F{index:04d}"
    return {
        "findings": findings,
        "skipped_files": skipped_files,
        "sca": {
            "status": ("not-selected" if "sca" not in scanners else
                       "catalog-missing" if catalog is None else "ran"),
            "unresolved_versions": unresolved_versions,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Catalog format: [{"package":"group:artifact","cve":"CVE-2099-12345",'
        '"severity":"high","ranges":[{"min_inclusive":"1.0","max_exclusive":"2.0"}]}].',
    )
    parser.add_argument("project", type=Path, help="local directory with the training project")
    parser.add_argument("--catalog", type=Path, help="JSON advisory catalog")
    args = parser.parse_args()
    if not args.project.is_dir():
        parser.error("project must be an existing directory")
    try:
        catalog = load_catalog(args.catalog)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(scan(args.project.resolve(), catalog), indent=2))


if __name__ == "__main__":
    main()
