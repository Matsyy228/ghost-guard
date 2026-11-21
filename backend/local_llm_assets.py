"""Install and verify the pinned Windows Qwen and llama.cpp assets."""

import argparse
import hashlib
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import Path
from shutil import copyfileobj
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1] / ".runtime" / "llm"
ENGINE_VERSION = "b12248"
ENGINE_DIRECTORY = f"llama-{ENGINE_VERSION}"
ENGINE_EXECUTABLE = "llama-server.exe"
MODEL_NAME = "Qwen2.5-1.5B-Instruct"
MODEL_REVISION = "91cad51170dc346986eccefdc2dd33a9da36ead9"


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    size: int
    sha256: str

    def matches(self, path):
        return (path.is_file() and not path.is_symlink() and path.stat().st_size == self.size
                and digest(path) == self.sha256)


WEIGHTS_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
WEIGHTS = Asset(
    WEIGHTS_NAME, f"https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/{MODEL_REVISION}/{WEIGHTS_NAME}",
    1117320736, "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e",
)
ENGINE_ARCHIVE = f"llama-{ENGINE_VERSION}-bin-win-vulkan-x64.zip"
ENGINE = Asset(
    ENGINE_ARCHIVE, f"https://github.com/ggml-org/llama.cpp/releases/download/{ENGINE_VERSION}/{ENGINE_ARCHIVE}",
    37891595, "3745e446c88e18cf20fd52f9df62867beb60d12fd0208c130fb4663117425826",
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class HTTPSOnly(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if urlsplit(new_url).scheme != "https":
            raise ValueError("Download redirected away from HTTPS.")
        return super().redirect_request(request, response, code, message, headers, new_url)


def install_asset(asset, directory, cache=None, *, offline=False):
    destination = directory / asset.name
    if asset.matches(destination):
        print(f"Verified existing {asset.name}", flush=True)
        return
    cached = cache / asset.name if cache is not None else None
    if cached is None or not cached.is_file():
        if offline:
            raise ValueError(f"Offline install needs the verified file {asset.name}. Supply it with -FromCache.")
        print(f"Downloading {asset.name} ({asset.size} bytes)", flush=True)
        source = build_opener(HTTPSOnly()).open(asset.url, timeout=30)
    else:
        source = cached.open("rb")
    partial = None
    try:
        with source, NamedTemporaryFile(dir=directory, suffix=".partial", delete=False) as output:
            partial = Path(output.name)
            remaining = asset.size
            checksum = hashlib.sha256()
            while chunk := source.read(min(1024 * 1024, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ValueError(f"Unexpected size for {asset.name}.")
                checksum.update(chunk)
                output.write(chunk)
            if remaining != 0 or checksum.hexdigest() != asset.sha256:
                raise ValueError(f"Size or SHA-256 mismatch for {asset.name}.")
        partial.replace(destination)
    finally:
        if partial is not None:
            partial.unlink(missing_ok=True)


def engine_members(archive):
    members = [item for item in archive.infolist()
               if item.filename == ENGINE_EXECUTABLE or item.filename.lower().endswith(".dll")]
    if any("/" in item.filename or "\\" in item.filename or ":" in item.filename for item in members):
        raise ValueError("Unexpected layout in the pinned engine ZIP.")
    if len({item.filename.casefold() for item in members}) != len(members):
        raise ValueError("Duplicate files in the pinned engine ZIP.")
    if ENGINE_EXECUTABLE not in {item.filename for item in members}:
        raise ValueError("Pinned ZIP has no server executable.")
    return members


def matching_member(archive, member, path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size != member.file_size:
        return False
    with archive.open(member) as source:
        return digest(path) == hashlib.file_digest(source, "sha256").hexdigest()


def check_engine(directory, *, repair=False):
    engine_dir = directory / ENGINE_DIRECTORY
    if engine_dir.resolve() != engine_dir or not ENGINE.matches(directory / ENGINE.name):
        raise ValueError("llama.cpp ZIP or installation directory failed verification.")
    with ZipFile(directory / ENGINE.name) as archive:
        members = engine_members(archive)
        expected = {member.filename.casefold() for member in members}
        if any(dll.name.casefold() not in expected for dll in engine_dir.glob("*.dll")):
            raise ValueError("Unexpected DLL in llama.cpp directory. Move the directory aside and run setup again.")
        if repair:
            engine_dir.mkdir(exist_ok=True)
        for member in members:
            path = engine_dir / member.filename
            if matching_member(archive, member, path):
                continue
            if not repair:
                raise ValueError("Installed llama.cpp files failed verification. Run setup again.")
            partial = None
            try:
                with archive.open(member) as source, NamedTemporaryFile(dir=engine_dir, delete=False) as output:
                    partial = Path(output.name)
                    copyfileobj(source, output)
                partial.replace(path)
            finally:
                if partial is not None:
                    partial.unlink(missing_ok=True)


def verify_install(directory):
    if directory.resolve() != directory or not WEIGHTS.matches(directory / WEIGHTS.name):
        raise ValueError("Qwen weights failed verification. Run setup again.")
    check_engine(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-cache", type=Path, help="directory with the two original verified downloads")
    parser.add_argument("--offline", action="store_true", help="use only installed files or --from-cache")
    args = parser.parse_args()
    try:
        if ROOT.resolve() != ROOT:
            raise ValueError("Move the installation to a local directory without filesystem links.")
        ROOT.mkdir(parents=True, exist_ok=True)
        for asset in (WEIGHTS, ENGINE):
            install_asset(asset, ROOT, args.from_cache, offline=args.offline)
        check_engine(ROOT, repair=True)
    except (OSError, ValueError, HTTPException) as exc:
        parser.exit(1, f"Local Qwen setup failed: {exc}\nCheck the connection or use -Offline -FromCache with verified files.\n")
    print("Local Qwen verified. Start GHOST//GUARD normally.")


if __name__ == "__main__":
    main()
