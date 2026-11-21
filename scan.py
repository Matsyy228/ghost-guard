"""Local defensive checks for Kotlin/Spring Boot training projects."""

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path

from analyzers.common import Kotlin, finding, submission_report
from analyzers.sast import kotlin_sast
from analyzers.sca import load_catalog, sca_findings
from analyzers.secrets import config_secrets, kotlin_secrets


SCANNERS = frozenset({"secrets", "sca", "sast"})
SKIP_DIRS = {".git", ".gradle", ".idea", "build", "out"}
MAX_FILE_SIZE = 1_000_000
CONFIG_VALUE = re.compile(r"^([\w.-]+)\s*[:=]\s*(.*?)\s*$")
CSRF_DISABLED = re.compile(
    r"\.\s*csrf\s*(?:\(\s*\)\s*\.\s*disable\s*\(\s*\)|"
    r"(?:\(\s*)?\{\s*(?:(?:\w+\s*->\s*)?\w+\s*\.\s*)?disable\s*\(\s*\)\s*\})"
)


def config_entries(path, source):
    parents = []
    is_yaml = path.endswith((".yaml", ".yml"))
    for number, line in enumerate(source.splitlines(), 1):
        if is_yaml and line.strip() in {"---", "..."}:
            parents.clear()
            continue
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


def configuration_sast(path, config):
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
    documents = []
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

        if path.suffix in {".kt", ".kts"}:
            document = Kotlin(relative, source)
            if "secrets" in scanners:
                findings.extend(kotlin_secrets(document))
            if "sast" in scanners and path.suffix == ".kt":
                documents.append(document)
                for match in CSRF_DISABLED.finditer(document.code):
                    findings.append(finding(
                        "sast", "spring-csrf-disabled", "medium", relative, document.line(match.start()),
                        "Отключена защита от CSRF",
                        "Проверьте способ аутентификации. Включите защиту для запросов с браузерными сессиями.",
                    ))
            if "sca" in scanners and path.name == "build.gradle.kts" and catalog is not None:
                findings.extend(sca_findings(root, path, document, catalog, unresolved_versions))
        else:
            config = list(config_entries(relative, source))
            if "secrets" in scanners:
                findings.extend(config_secrets(relative, config))
            if "sast" in scanners:
                findings.extend(configuration_sast(relative, config))

    if "sast" in scanners:
        findings.extend(kotlin_sast(documents))
    findings.sort(key=lambda item: (item["file"], item["line"], item["rule"], item.get("advisoryId", "")))
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


def release_gate(report, scanners=SCANNERS):
    counts = Counter(finding["severity"] for finding in report["findings"])
    missing = SCANNERS.difference(scanners)
    if report["sca"]["status"] != "ran":
        missing |= {"sca"}
    incomplete = bool(missing or report["skipped_files"] or report["sca"]["unresolved_versions"])
    if counts["critical"] or counts["high"]:
        status = "BLOCK"
    elif counts["medium"] or counts["low"] or incomplete:
        status = "WARNING"
    else:
        status = "PASS"
    return {
        "status": status,
        "counts": {level: counts[level] for level in ("critical", "high", "medium", "low")},
        "missing_scanners": sorted(missing),
        "skipped_files": len(report["skipped_files"]),
        "unresolved_versions": len(report["sca"]["unresolved_versions"]),
    }


def main():
    from backend.service import DEMO, MAX_CATALOG, scan_upload
    from backend.source_policy import read_local_archive

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="approved local training ZIP or the bundled demo directory")
    parser.add_argument("--catalog", type=Path, help="official Maven JSON catalog or bundled demo format")
    parser.add_argument("--submission", action="store_true", help="emit the organizer's JSON report format")
    args = parser.parse_args()
    try:
        if "://" in args.project or args.project.startswith(("\\\\", "//")):
            raise ValueError("remote project sources are not supported")
        local = Path(args.project)
        if local.absolute() == DEMO / "project":
            report = scan(local.resolve(), load_catalog(args.catalog))
        else:
            if local.is_dir():
                raise ValueError("pack the local training project as ZIP and approve it with python -m backend.source_policy")
            archive = read_local_archive(local)
            catalog = None
            if args.catalog is not None:
                with args.catalog.open("rb") as stream:
                    catalog = stream.read(MAX_CATALOG + 1)
            report = scan_upload(archive, catalog)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(submission_report(report) if args.submission else report, indent=2))


if __name__ == "__main__":
    main()
