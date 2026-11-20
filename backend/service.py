"""Adapt uploaded projects and the bundled demo to the existing scanners."""

import re
import stat
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

import scan


ROOT = Path(__file__).resolve().parents[1]
DEMO = Path(__file__).resolve().parent / "demo"
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_CATALOG = 512 * 1024
MAX_UNCOMPRESSED = 64 * 1024 * 1024
MAX_ENTRIES = 4000
SOURCE_EXTENSIONS = {".kt", ".kts", ".yaml", ".yml", ".properties"}
INVALID_NAME = re.compile(r'[\\:*?"<>|\x00-\x1f]')
WINDOWS_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?", re.I)


class InvalidInput(ValueError):
    """The supplied project or catalog could not be processed."""


def archive_path(name):
    parts = name.removesuffix("/").split("/")
    if any(
        not part or part in {".", ".."} or part.endswith((" ", "."))
        or INVALID_NAME.search(part) or WINDOWS_DEVICE.fullmatch(part)
        for part in parts
    ):
        raise InvalidInput("ZIP содержит недопустимый путь.")
    return parts


def extract_sources(data, root):
    try:
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES or sum(entry.file_size for entry in entries) > MAX_UNCOMPRESSED:
                raise InvalidInput("ZIP превышает лимит по числу файлов или распакованному размеру.")
            paths = set()
            for entry in entries:
                parts = archive_path(entry.orig_filename)
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR} or entry.flag_bits & 1:
                    raise InvalidInput("ZIP содержит ссылку, специальный или зашифрованный файл.")
                path = root.joinpath(*parts)
                supported = path.suffix in SOURCE_EXTENSIONS or path.name == "gradle.lockfile"
                if entry.is_dir() or not supported or scan.SKIP_DIRS.intersection(parts[:-1]):
                    continue
                key = tuple(part.casefold() for part in parts)
                if key in paths:
                    raise InvalidInput("ZIP содержит совпадающие имена файлов.")
                paths.add(key)
                if entry.file_size > scan.MAX_FILE_SIZE:
                    raise InvalidInput("Файл исходного кода или конфигурации превышает 1 МБ.")
                with archive.open(entry) as stream:
                    source = stream.read(scan.MAX_FILE_SIZE + 1)
                if len(source) > scan.MAX_FILE_SIZE:
                    raise InvalidInput("Файл исходного кода или конфигурации превышает 1 МБ.")
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as output:
                    output.write(source)
            if not paths:
                raise InvalidInput("В ZIP нет исходников Kotlin, файлов Gradle или конфигурации Spring.")
    except (BadZipFile, OSError, RuntimeError, NotImplementedError, ValueError) as exc:
        if isinstance(exc, InvalidInput):
            raise
        raise InvalidInput("Не удалось распаковать ZIP. Проверьте формат и имена файлов.") from exc


def demo_project():
    return DEMO / "project", scan.load_catalog(DEMO / "catalog.json")


@contextmanager
def upload_project(archive, catalog_data):
    if not archive or len(archive) > MAX_ARCHIVE:
        raise InvalidInput("Нужен ZIP-архив размером до 8 МБ.")
    if catalog_data is not None and len(catalog_data) > MAX_CATALOG:
        raise InvalidInput("JSON-справочник должен быть меньше 512 КиБ.")

    runtime = ROOT / ".runtime"
    runtime.mkdir(exist_ok=True)
    if runtime.resolve() != runtime:
        raise InvalidInput("Каталог .runtime должен находиться в папке приложения.")
    with TemporaryDirectory(prefix="scan-", dir=runtime) as workspace:
        work = Path(workspace)
        project = work / "project"
        project.mkdir()
        extract_sources(archive, project)
        catalog = None
        if catalog_data is not None:
            catalog_path = work / "catalog.json"
            catalog_path.write_bytes(catalog_data)
            try:
                catalog = scan.load_catalog(catalog_path)
            except (ValueError, RecursionError) as exc:
                raise InvalidInput("Неверный формат справочника SCA. Пример есть в README.") from exc
        yield project, catalog


def scan_demo():
    return scan.scan(*demo_project())


def scan_upload(archive, catalog_data):
    with upload_project(archive, catalog_data) as project:
        return scan.scan(*project)
