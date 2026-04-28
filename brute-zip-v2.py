#!/usr/bin/env python3
"""
ZIP password recovery helper for authorized labs and CTF exercises.

It tests passwords without extracting files on every attempt, streams large
wordlists, and can split work across multiple CPU cores.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterable, Iterator

try:
    import pyzipper
except ImportError:  # pyzipper is only required for AES-encrypted ZIP files.
    pyzipper = None


READ_SIZE = 1024 * 1024
DEFAULT_CHUNK_SIZE = 500
DEFAULT_WORKERS = max(1, min(os.cpu_count() or 1, 8))
ZIP_ERRORS = (RuntimeError, zipfile.BadZipFile, EOFError, OSError, ValueError)
AES_EXTRA_ID = 0x9901
SUPPORTED_RULES = {"case", "leet"}


class BruteZipError(Exception):
    """User-facing error."""


@dataclasses.dataclass(frozen=True)
class ArchiveInfo:
    path: Path
    encrypted_members: tuple[str, ...]
    test_member: str
    test_member_size: int
    uses_aes: bool


@dataclasses.dataclass(frozen=True)
class WorkerResult:
    attempted: int
    password: bytes | None = None
    error: str | None = None


class Progress:
    def __init__(self, total: int | None, enabled: bool) -> None:
        self.total = total
        self.enabled = enabled
        self.started_at = time.monotonic()
        self.last_render = 0.0

    def update(self, attempted: int, *, done: bool = False) -> None:
        if not self.enabled:
            return

        now = time.monotonic()
        if not done and now - self.last_render < 0.2:
            return

        self.last_render = now
        elapsed = max(now - self.started_at, 0.001)
        rate = attempted / elapsed

        if self.total:
            percent = min(attempted / self.total, 1.0)
            filled = int(percent * 32)
            bar = "#" * filled + "." * (32 - filled)
            remaining = max(self.total - attempted, 0)
            eta = format_duration(remaining / rate) if rate else "?"
            message = (
                f"\r[{bar}] {attempted}/{self.total} "
                f"({percent * 100:5.1f}%) {rate:,.0f}/s ETA {eta}"
            )
        else:
            message = f"\rIntentos: {attempted} | {rate:,.0f}/s"

        sys.stderr.write(message)
        if done:
            sys.stderr.write("\n")
        sys.stderr.flush()


def format_duration(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)

    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def open_zip(path: str | Path):
    if pyzipper is not None:
        return pyzipper.AESZipFile(path)
    return zipfile.ZipFile(path)


def has_aes_extra(info: zipfile.ZipInfo) -> bool:
    extra = info.extra
    offset = 0

    while offset + 4 <= len(extra):
        header_id = int.from_bytes(extra[offset : offset + 2], "little")
        data_size = int.from_bytes(extra[offset + 2 : offset + 4], "little")
        offset += 4

        if header_id == AES_EXTRA_ID:
            return True

        offset += data_size

    return False


def inspect_archive(path: Path) -> ArchiveInfo:
    if not path.is_file():
        raise BruteZipError(f"No existe el archivo ZIP: {path}")

    try:
        with zipfile.ZipFile(path) as archive:
            file_infos = [item for item in archive.infolist() if not item.is_dir()]
    except zipfile.BadZipFile as exc:
        raise BruteZipError(f"Archivo ZIP invalido: {path}") from exc

    if not file_infos:
        raise BruteZipError("El ZIP no contiene archivos probables para validar.")

    encrypted_infos = [item for item in file_infos if item.flag_bits & 0x1]
    if not encrypted_infos:
        raise BruteZipError("El ZIP no parece estar protegido con contraseña.")

    uses_aes = any(item.compress_type == 99 or has_aes_extra(item) for item in encrypted_infos)
    if uses_aes and pyzipper is None:
        raise BruteZipError(
            "Este ZIP usa cifrado AES. Instala pyzipper con: python -m pip install pyzipper"
        )

    non_empty_infos = [item for item in encrypted_infos if item.file_size > 0]
    test_info = min(non_empty_infos or encrypted_infos, key=lambda item: item.file_size)
    return ArchiveInfo(
        path=path,
        encrypted_members=tuple(item.filename for item in encrypted_infos),
        test_member=test_info.filename,
        test_member_size=test_info.file_size,
        uses_aes=uses_aes,
    )


def parse_rules(raw_rules: str) -> tuple[str, ...]:
    if not raw_rules:
        return ()

    rules = tuple(rule.strip().lower() for rule in raw_rules.split(",") if rule.strip())
    unknown = sorted(set(rules) - SUPPORTED_RULES)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"reglas no soportadas: {', '.join(unknown)}; usa: case, leet"
        )
    return rules


def append_digits_type(value: str) -> int:
    try:
        digits = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("debe ser un numero entero") from exc

    if digits < 1 or digits > 4:
        raise argparse.ArgumentTypeError("usa un valor entre 1 y 4")
    return digits


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("debe ser un numero entero") from exc

    if number < 1:
        raise argparse.ArgumentTypeError("debe ser mayor que cero")
    return number


def non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("debe ser un numero entero") from exc

    if number < 0:
        raise argparse.ArgumentTypeError("debe ser cero o mayor")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recupera contraseñas de ZIPs propios, de laboratorio o CTF.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("zipfile", nargs="?", help="ruta del archivo ZIP protegido")
    parser.add_argument("wordlist", nargs="?", help="ruta del diccionario")
    parser.add_argument(
        "-w",
        "--workers",
        type=positive_int,
        default=DEFAULT_WORKERS,
        help="procesos paralelos",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=non_negative_int,
        help="filtra candidatos por longitud en bytes",
    )
    parser.add_argument(
        "--chunk-size",
        type=positive_int,
        default=DEFAULT_CHUNK_SIZE,
        help="candidatos por lote enviado a cada proceso",
    )
    parser.add_argument(
        "--rules",
        type=parse_rules,
        default=(),
        metavar="case,leet",
        help="mutaciones simples del diccionario",
    )
    parser.add_argument(
        "--suffix",
        action="append",
        default=[],
        help="sufijo literal a probar; se puede repetir",
    )
    parser.add_argument(
        "--append-digits",
        type=append_digits_type,
        metavar="N",
        help="agrega sufijos numericos 0..9, 00..99, etc. hasta N=4",
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="codificacion para mostrar candidatos y convertir sufijos",
    )
    parser.add_argument(
        "--unique",
        action="store_true",
        help="elimina candidatos duplicados globalmente; consume mas memoria",
    )
    parser.add_argument(
        "--skip",
        type=non_negative_int,
        default=0,
        help="omite los primeros N candidatos generados",
    )
    parser.add_argument(
        "--limit",
        type=positive_int,
        help="limita el numero de candidatos probados",
    )
    parser.add_argument(
        "--no-count",
        action="store_true",
        help="no hace pasada previa para calcular progreso total",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="desactiva la barra de progreso",
    )
    parser.add_argument(
        "--no-verify-all",
        action="store_true",
        help="no valida la clave contra todos los archivos cifrados al final",
    )
    parser.add_argument(
        "--extract-to",
        type=Path,
        help="extrae el ZIP aqui solo despues de encontrar la contraseña",
    )
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = build_parser()

    if argv:
        args = parser.parse_args(argv)
    else:
        args = interactive_args(parser)

    if not args.zipfile or not args.wordlist:
        parser.error("se requieren zipfile y wordlist")

    return args


def interactive_args(parser: argparse.ArgumentParser) -> argparse.Namespace:
    print("Modo interactivo. Tambien puedes usar: python brute-zip.py archivo.zip wordlist.txt")
    zip_path = input("Ruta del archivo ZIP protegido: ").strip()
    wordlist_path = input("Ruta del diccionario: ").strip()

    argv = [zip_path, wordlist_path]
    length_based = input("Filtrar por longitud? (s/N): ").strip().lower()
    if length_based == "s":
        length = input("Longitud de contraseña en bytes: ").strip()
        argv.extend(["--length", length])

    workers = input(f"Procesos paralelos [{DEFAULT_WORKERS}]: ").strip()
    if workers:
        argv.extend(["--workers", workers])

    return parser.parse_args(argv)


def build_suffixes(args: argparse.Namespace) -> tuple[bytes, ...]:
    suffixes: list[bytes] = []

    for suffix in args.suffix:
        suffixes.append(suffix.encode(args.encoding))

    if args.append_digits:
        stop = 10**args.append_digits
        suffixes.extend(f"{number:0{args.append_digits}d}".encode("ascii") for number in range(stop))

    return tuple(dedupe_preserving_order(suffixes))


def dedupe_preserving_order(values: Iterable[bytes]) -> Iterator[bytes]:
    seen: set[bytes] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        yield value


def expand_candidate(base: bytes, rules: tuple[str, ...], suffixes: tuple[bytes, ...]) -> Iterator[bytes]:
    variants = [base]

    if "case" in rules:
        variants.extend((base.lower(), base.upper(), base.capitalize()))

    if "leet" in rules:
        table = bytes.maketrans(b"aeiostAEIOST", b"431057431057")
        variants.append(base.translate(table))

    normalized = tuple(dedupe_preserving_order(variants))
    yield from normalized

    for suffix in suffixes:
        for candidate in normalized:
            yield candidate + suffix


def iter_candidates(
    wordlist_path: Path,
    *,
    length: int | None,
    rules: tuple[str, ...],
    suffixes: tuple[bytes, ...],
    unique: bool,
    skip: int,
    limit: int | None,
) -> Iterator[bytes]:
    seen: set[bytes] = set()
    yielded = 0

    with wordlist_path.open("rb") as handle:
        for raw_line in handle:
            base = raw_line.rstrip(b"\r\n")

            for candidate in expand_candidate(base, rules, suffixes):
                if length is not None and len(candidate) != length:
                    continue

                if unique:
                    if candidate in seen:
                        continue
                    seen.add(candidate)

                if skip:
                    skip -= 1
                    continue

                yield candidate
                yielded += 1

                if limit is not None and yielded >= limit:
                    return


def chunked(candidates: Iterator[bytes], chunk_size: int) -> Iterator[list[bytes]]:
    chunk: list[bytes] = []

    for candidate in candidates:
        chunk.append(candidate)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []

    if chunk:
        yield chunk


def count_candidates(args: argparse.Namespace, suffixes: tuple[bytes, ...]) -> int | None:
    if args.no_count or args.no_progress:
        return None

    return sum(
        1
        for _ in iter_candidates(
            Path(args.wordlist),
            length=args.length,
            rules=args.rules,
            suffixes=suffixes,
            unique=args.unique,
            skip=args.skip,
            limit=args.limit,
        )
    )


def read_encrypted_member(archive, member_name: str, password: bytes) -> None:
    with archive.open(member_name, "r", pwd=password) as member:
        while member.read(READ_SIZE):
            pass


def try_password_chunk(archive_path: str, member_name: str, candidates: list[bytes]) -> WorkerResult:
    attempted = 0

    try:
        with open_zip(archive_path) as archive:
            for password in candidates:
                attempted += 1
                try:
                    read_encrypted_member(archive, member_name, password)
                except ZIP_ERRORS:
                    continue

                return WorkerResult(attempted=attempted, password=password)
    except NotImplementedError as exc:
        return WorkerResult(attempted=attempted, error=str(exc))
    except Exception as exc:  # Defensive boundary between worker and parent process.
        return WorkerResult(attempted=attempted, error=f"{type(exc).__name__}: {exc}")

    return WorkerResult(attempted=attempted)


def crack_password(
    args: argparse.Namespace,
    archive_info: ArchiveInfo,
    suffixes: tuple[bytes, ...],
    total: int | None,
) -> tuple[bytes | None, int]:
    candidate_chunks = chunked(
        iter_candidates(
            Path(args.wordlist),
            length=args.length,
            rules=args.rules,
            suffixes=suffixes,
            unique=args.unique,
            skip=args.skip,
            limit=args.limit,
        ),
        args.chunk_size,
    )
    progress = Progress(total, enabled=not args.no_progress)
    workers = args.workers

    if workers == 1:
        return crack_single_process(args, archive_info, candidate_chunks, progress)

    return crack_multi_process(args, archive_info, candidate_chunks, progress, workers)


def crack_single_process(
    args: argparse.Namespace,
    archive_info: ArchiveInfo,
    candidate_chunks: Iterator[list[bytes]],
    progress: Progress,
) -> tuple[bytes | None, int]:
    attempted = 0

    for candidates in candidate_chunks:
        result = try_password_chunk(str(archive_info.path), archive_info.test_member, candidates)
        attempted += result.attempted
        progress.update(attempted)

        if result.error:
            raise BruteZipError(result.error)
        if result.password is not None:
            progress.update(attempted, done=True)
            return result.password, attempted

    progress.update(attempted, done=True)
    return None, attempted


def crack_multi_process(
    args: argparse.Namespace,
    archive_info: ArchiveInfo,
    candidate_chunks: Iterator[list[bytes]],
    progress: Progress,
    workers: int,
) -> tuple[bytes | None, int]:
    attempted = 0
    pending: set[concurrent.futures.Future[WorkerResult]] = set()
    exhausted = False
    max_pending = max(workers * 2, 1)

    def submit_next(executor: concurrent.futures.ProcessPoolExecutor) -> None:
        nonlocal exhausted
        if exhausted:
            return

        try:
            candidates = next(candidate_chunks)
        except StopIteration:
            exhausted = True
            return

        pending.add(
            executor.submit(
                try_password_chunk,
                str(archive_info.path),
                archive_info.test_member,
                candidates,
            )
        )

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        for _ in range(max_pending):
            submit_next(executor)

        while pending:
            done, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for future in done:
                result = future.result()
                attempted += result.attempted
                progress.update(attempted)

                if result.error:
                    for item in pending:
                        item.cancel()
                    raise BruteZipError(result.error)

                if result.password is not None:
                    for item in pending:
                        item.cancel()
                    progress.update(attempted, done=True)
                    return result.password, attempted

                submit_next(executor)

    progress.update(attempted, done=True)
    return None, attempted


def verify_password(archive_info: ArchiveInfo, password: bytes, *, all_members: bool) -> bool:
    members = archive_info.encrypted_members if all_members else (archive_info.test_member,)

    try:
        with open_zip(archive_info.path) as archive:
            for member_name in members:
                read_encrypted_member(archive, member_name, password)
    except ZIP_ERRORS:
        return False

    return True


def safe_extract(archive_info: ArchiveInfo, destination: Path, password: bytes) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    with open_zip(archive_info.path) as archive:
        for item in archive.infolist():
            target = (root / item.filename).resolve()

            try:
                target.relative_to(root)
            except ValueError as exc:
                raise BruteZipError(f"Ruta peligrosa dentro del ZIP: {item.filename}") from exc

            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item, "r", pwd=password) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def display_password(password: bytes, encoding: str) -> str:
    return password.decode(encoding, errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    zip_path = Path(args.zipfile)
    wordlist_path = Path(args.wordlist)

    if not wordlist_path.is_file():
        raise BruteZipError(f"No existe el diccionario: {wordlist_path}")

    suffixes = build_suffixes(args)
    archive_info = inspect_archive(zip_path)
    total = count_candidates(args, suffixes)

    print(
        f"Archivo: {archive_info.path} | miembros cifrados: {len(archive_info.encrypted_members)} | "
        f"prueba rapida: {archive_info.test_member} ({archive_info.test_member_size} bytes)"
    )
    print(f"Workers: {args.workers} | chunk: {args.chunk_size} | AES: {'si' if archive_info.uses_aes else 'no'}")

    password, attempted = crack_password(args, archive_info, suffixes, total)

    if password is None:
        print(f"Contraseña no encontrada tras {attempted} intentos.")
        return 1

    rendered = display_password(password, args.encoding)
    print(f"Contraseña encontrada: {rendered}")

    if not args.no_verify_all:
        print("Verificando contraseña contra todos los miembros cifrados...")
        if not verify_password(archive_info, password, all_members=True):
            print("Aviso: la contraseña abre el miembro de prueba, pero no todo el ZIP.")

    if args.extract_to:
        safe_extract(archive_info, args.extract_to, password)
        print(f"Contenido extraido en: {args.extract_to}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.", file=sys.stderr)
        raise SystemExit(130)
    except BruteZipError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)
