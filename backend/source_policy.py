"""Operator-managed access to local training archives."""

import argparse
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from re import fullmatch
from stat import S_ISDIR, S_ISREG
from zipfile import is_zipfile


MAX_ARCHIVE = 8 * 1024 * 1024
DEFAULT_APPROVALS = Path(__file__).resolve().parents[1] / ".runtime" / "approved-sources"


class SourcePolicyError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def valid_digest(digest):
    return fullmatch(r"[a-f0-9]{64}", digest) is not None


class SourcePolicy:
    def __init__(self, directory=DEFAULT_APPROVALS):
        self.directory = Path(directory).absolute()

    def marker(self, digest):
        if not valid_digest(digest):
            raise ValueError("Ожидается SHA-256 из 64 строчных шестнадцатеричных символов.")
        if self.directory.resolve() != self.directory:
            raise OSError("Каталог разрешений должен быть локальным каталогом без ссылок.")
        try:
            if not S_ISDIR(self.directory.lstat().st_mode):
                raise OSError("Ожидается каталог разрешений.")
        except FileNotFoundError:
            pass
        return self.directory / digest

    def require(self, archive):
        try:
            marker = self.marker(sha256(archive).hexdigest())
            entry = marker.lstat()
            if S_ISREG(entry.st_mode) and entry.st_size == 0:
                return
        except FileNotFoundError:
            pass
        except (OSError, RuntimeError):
            raise SourcePolicyError("source-policy-unavailable",
                                    "Сервер не может прочитать список разрешённых источников.") from None
        raise SourcePolicyError("source-not-approved",
                                "Этот ZIP не разрешён. Попросите оператора допустить точный учебный архив.")

    def approve(self, archive):
        digest = sha256(archive).hexdigest()
        marker = self.marker(digest)
        marker.parent.mkdir(parents=True, exist_ok=True)
        try:
            marker.open("xb").close()
        except FileExistsError:
            self.require(archive)
        return digest

    def revoke(self, digest):
        self.marker(digest).unlink(missing_ok=True)


def read_local_archive(path):
    if str(path).startswith(("\\\\", "//")):
        raise ValueError("Укажите локальный ZIP-файл.")
    path = Path(path)
    resolved = path.resolve(strict=True)
    if str(resolved).startswith(("\\\\", "//")) or not resolved.is_file():
        raise ValueError("Укажите локальный ZIP-файл.")
    with resolved.open("rb") as stream:
        archive = stream.read(MAX_ARCHIVE + 1)
    if not archive or len(archive) > MAX_ARCHIVE:
        raise ValueError("Нужен ZIP-архив размером до 8 МБ.")
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("approve", help="approve the exact bytes of an authorized training ZIP").add_argument("archive")
    commands.add_parser("revoke", help="revoke approval using its SHA-256").add_argument("sha256")
    args = parser.parse_args()
    policy = SourcePolicy()
    try:
        if args.action == "approve":
            archive = read_local_archive(args.archive)
            if not is_zipfile(BytesIO(archive)):
                raise ValueError("Файл не является ZIP-архивом.")
            print(policy.approve(archive))
        else:
            policy.revoke(args.sha256)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
