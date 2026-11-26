#!/usr/bin/env python3
"""
Encrypt every HTML file in public-encrypted/ with StatiCrypt and write the protected
copies to public/ (the folder GitHub Pages serves). Plaintext source is local-only:
public-encrypted/ is gitignored and never tracked.

Password strategy: derived passwords (default)
  Each file's password = HMAC-SHA256(ENCRYPT_SECRET, relative_path), base64, 24 chars.
  One master secret in your password manager, a different password per page, any
  password regenerable from secret + path. The secret never touches the repo.
  ENCRYPT_PASSWORD=<value> in .env switches EVERY file to that single password. A leak
  then exposes every page, not one. Remove the line to go back to derived passwords.

Usage:
    python3 scripts/encrypt/encrypt_public.py                  # encrypt all -> public/, check every output
    python3 scripts/encrypt/encrypt_public.py --skip-unchanged # skip pages whose fingerprint is current
    python3 scripts/encrypt/encrypt_public.py --file reports/q1.html
    python3 scripts/encrypt/encrypt_public.py --show           # counts + where the secret lives, no values
    python3 scripts/encrypt/encrypt_public.py --count          # the number of pages a run would encrypt, nothing else
    python3 scripts/encrypt/encrypt_public.py --show --reveal  # the password table, terminal only, never in CI
    python3 scripts/encrypt/encrypt_public.py --new-password c-x/page/index.html --code ABC
                                       # new page password ThoughtfulX<CODE>_<4 random>, saved + copied to the clipboard
    python3 scripts/encrypt/encrypt_public.py --copy c-x/page/index.html   # copy a page's password to the clipboard

Per-page passwords: a page listed in .env.page-passwords (gitignored, one `relative/path.html=password` per line)
uses that password instead of the derived one. --new-password writes the line; nothing ever prints the value.

What a run never does: print a password (the table needs --reveal on a TTY), encrypt a page
that is already StatiCrypt output (that would wrap it twice), fall back to StatiCrypt's own
page when scripts/encrypt/template.html is missing, take a source through a symlink, or skip
a page on timestamps alone (the fingerprint covers source, password, template, salt config
and the StatiCrypt version).

Requirements: Node.js (npx). StatiCrypt is pinned to STATICRYPT_VERSION below (staticrypt@3.5.4): npx fetches that
one version the first time and reuses it after. Each page's password reaches StatiCrypt as STATICRYPT_PASSWORD,
never on the command line.
"""

import argparse
import base64
import functools
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ---- CONFIG (the only block that differs between the shared template and its scaffold copies) ----
WORKSPACE_FROM = "file"          # "file": repo root is 2 levels above this script; "cwd": run from the repo root
OUTPUT_SUBDIR = "public"         # the folder Pages serves
DEFAULT_MODE = "derived"         # "derived": per-file HMAC unless ENCRYPT_PASSWORD is set; "shared": ENCRYPT_PASSWORD required
ALLOW_DERIVED = True             # "shared" repos may still opt a page into a derived password with --derived
# ---- END CONFIG ----

STATICRYPT_VERSION = "3.5.4"
STATICRYPT_PKG = f"staticrypt@{STATICRYPT_VERSION}"
WORKSPACE = Path.cwd() if WORKSPACE_FROM == "cwd" else Path(__file__).resolve().parent.parent.parent

# Load .env from the workspace root if present (stdlib only; a real env var wins).
_env_file = WORKSPACE / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

SOURCE_DIR = WORKSPACE / "public-encrypted"
OUTPUT_DIR = WORKSPACE / OUTPUT_SUBDIR
TEMPLATE = Path(__file__).resolve().parent / "template.html"
CONFIG_FILE = WORKSPACE / ".staticrypt.json"          # holds the salt every page was encrypted with
FINGERPRINT_FILE = Path(__file__).resolve().parent / "encrypt-manifest.json"
PAGE_PASSWORDS_FILE = WORKSPACE / ".env.page-passwords"   # gitignored by `.env.*`; per-page passwords, never committed
PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"   # no 0/O, 1/l/I: easy to read and type

HTML_EXT = {".html", ".htm"}
CONFIG_MARK = "staticryptConfig"
PAYLOAD_MARKER = "staticryptEncryptedMsgUniqueVariableName"


SALT_KEY = "staticryptSaltUniqueVariableName"
CONFIG_KEYS = {PAYLOAD_MARKER, "isRememberEnabled", "rememberDurationInDays", SALT_KEY}
# StatiCrypt's own placeholder pattern (lib/formater.js renderTemplate in 3.5.4) and the 3 placeholders it fills here.
_PLACEHOLDER = re.compile(r"/\*\[\|\s*(\w+)\s*\|]\*/\s*0")
RENDERED = ("js_staticrypt", "is_remember_enabled", "staticrypt_config")
# sha256 of the script staticrypt@3.5.4 puts in js_staticrypt (cli/helpers.js buildStaticryptJS); it's the same
# for every page and changes only with the StatiCrypt version, which STATICRYPT_VERSION pins.
STATICRYPT_JS_SHA256 = "1df62c0e4e69ea65e3fee9e9864fc55249fd878771bbbf7414efaf30dc2f02f4"
_HEX = re.compile(r"[0-9a-f]+")


@functools.lru_cache(maxsize=4)
def _rendered_shape(template_text: str):
    """The template as a pattern: its own text kept exactly, each placeholder StatiCrypt fills a capture."""
    parts = _PLACEHOLDER.split(template_text)
    literals, names = parts[0::2], parts[1::2]
    if sorted(names) != sorted(RENDERED):
        return None
    pattern = re.escape(literals[0])
    for name, literal in zip(names, literals[1:]):
        pattern += f"(?P<{name}>.*?)" + re.escape(literal)
    return re.compile(pattern, re.S)


def is_staticrypt_output(path: Path, template: Path = None) -> bool:
    """True only for a page StatiCrypt 3.5.4 rendered from this repo's template (scripts/encrypt/template.html): the
    page is the template character for character except its 3 placeholders, and those hold exactly what StatiCrypt
    writes there - its own script (sha256 pinned above), true or false, and one settings object with StatiCrypt's 4
    keys, the encrypted part as hex in StatiCrypt's shape (64-character signature, 32-character IV, whole 16-byte
    blocks of ciphertext) and a 32-character hex salt. Anything else is a readable page, including one that quotes
    the settings in a script string, a comment or its text, so the source check encrypts it and the output check
    never counts it."""
    template = TEMPLATE if template is None else template
    try:
        text = path.read_bytes().decode("utf-8")
        shape = _rendered_shape(template.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return False
    m = shape.fullmatch(text) if shape else None
    if not m:
        return False
    if hashlib.sha256(m["js_staticrypt"].encode("utf-8")).hexdigest() != STATICRYPT_JS_SHA256:
        return False
    if m["is_remember_enabled"] not in ("true", "false"):
        return False
    try:
        cfg = json.loads(m["staticrypt_config"])
    except ValueError:
        return False
    if not isinstance(cfg, dict) or set(cfg) != CONFIG_KEYS:
        return False
    payload, salt = cfg[PAYLOAD_MARKER], cfg[SALT_KEY]
    return (isinstance(payload, str) and _HEX.fullmatch(payload) is not None
            and len(payload) >= 64 + 32 + 32 and (len(payload) - 96) % 32 == 0
            and isinstance(salt, str) and len(salt) == 32 and _HEX.fullmatch(salt) is not None
            and isinstance(cfg["isRememberEnabled"], bool)
            and type(cfg["rememberDurationInDays"]) is int)

IN_CI = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))


# ---------------------------------------------------------------- passwords
def derive_password(master_secret: str, relative_path: str) -> str:
    digest = hmac.new(master_secret.encode("utf-8"), relative_path.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)[:24].decode("ascii")


def load_page_passwords() -> dict:
    out = {}
    if PAGE_PASSWORDS_FILE.exists():
        for line in PAGE_PASSWORDS_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and v.strip():
                    out[k.strip()] = v.strip()
    return out


def save_page_password(rel: str, password: str) -> None:
    pw = load_page_passwords()
    pw[rel] = password
    body = "# Per-page StatiCrypt passwords (gitignored). Format: relative/path.html=password. Never commit or paste.\n"
    body += "".join(f"{k}={v}\n" for k, v in sorted(pw.items()))
    PAGE_PASSWORDS_FILE.write_text(body)
    os.chmod(PAGE_PASSWORDS_FILE, 0o600)


def copy_to_clipboard(value: str) -> None:
    try:
        subprocess.run(["pbcopy"], input=value, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        sys.exit("Couldn't reach the clipboard (pbcopy is macOS only), so nothing was copied. Use --show --reveal on a terminal.")


def new_page_password(code: str) -> str:
    import secrets
    code = re.sub(r"[^A-Za-z0-9]", "", code or "").upper()
    if not code:
        sys.exit("ERROR: --code needs the client code, e.g. --code NMJ.")
    return f"ThoughtfulX{code}_" + "".join(secrets.choice(PW_ALPHABET) for _ in range(4))


# ---------------------------------------------------------------- fingerprint
def file_fingerprint(src: Path, password: str, template_bytes: bytes, config_bytes: bytes) -> str:
    """Everything that changes the encrypted output. Timestamps are not part of it, so a password,
    template, salt or tool change with unchanged source forces fresh output."""
    h = hashlib.sha256()
    for part in (src.read_bytes(), password.encode("utf-8"), template_bytes, config_bytes, STATICRYPT_VERSION.encode("ascii")):
        h.update(part)
        h.update(b"\x00")
    return h.hexdigest()


def load_fingerprints() -> dict:
    if FINGERPRINT_FILE.exists():
        try:
            return json.loads(FINGERPRINT_FILE.read_text())
        except ValueError:
            return {}
    return {}


def save_fingerprints(m: dict) -> None:
    FINGERPRINT_FILE.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")



# ---------------------------------------------------------------- source selection (never through a symlink)
def real_file_inside(p: Path, base: Path) -> bool:
    try:
        return p.resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def source_files(base: Path) -> list:
    """Every regular file under base, walked WITHOUT following symlinks. A symlink anywhere in the source
    tree (file or directory) is a hard error: it could materialise a file from outside the tree into the release."""
    out = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for d in list(dirnames):
            if (Path(dirpath) / d).is_symlink():
                sys.exit(f"ERROR: {(Path(dirpath) / d).relative_to(base).as_posix()}/ is a symlinked directory inside {base.name}/ - sources must be real files")
        for f in filenames:
            p = Path(dirpath) / f
            if p.is_symlink() or not real_file_inside(p, base):
                sys.exit(f"ERROR: {p.relative_to(base).as_posix()} is a symlink inside {base.name}/ - sources must be real files")
            out.append(p)
    return sorted(out)


def is_page(p: Path) -> bool:
    """A page this script encrypts: .html or .htm, any letter case (.HTML, .Htm)."""
    return p.suffix.lower() in HTML_EXT


def select_pages(base: Path) -> list:
    """The one page selection: every run, --show and --count use it, so the number a member approves is the
    number of pages make encrypt then processes."""
    return [f for f in source_files(base) if is_page(f)]



# ---------------------------------------------------------------- staticrypt
def staticrypt_env(password: str) -> dict:
    """The child's environment: the password goes to StatiCrypt as STATICRYPT_PASSWORD, never on the command
    line, so it isn't visible in the process list while the tool runs."""
    env = dict(os.environ)
    env["STATICRYPT_PASSWORD"] = password
    return env


NODE_MISSING = ("Node.js is missing, so nothing was encrypted. Install Node.js (ask Claude for the command for your "
                "computer), then run `make encrypt`.")


def encrypt_file(src: Path, output_dir: Path, password: str) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["npx", "--yes", STATICRYPT_PKG, str(src), "-d", str(output_dir), "--short"]
    if CONFIG_FILE.exists():
        cmd += ["--config", CONFIG_FILE.name]          # relative: StatiCrypt prefixes ./ to the path
    if TEMPLATE.exists():
        cmd += ["--template", str(TEMPLATE)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(WORKSPACE), env=staticrypt_env(password),
                                timeout=300)
    except FileNotFoundError:
        sys.exit(NODE_MISSING)
    except subprocess.TimeoutExpired:
        print("    StatiCrypt took too long and was stopped, so this page wasn't encrypted. Run `make encrypt` again.",
              file=sys.stderr)
        return False
    if result.returncode != 0:
        # stderr may echo the command line: report the exit code only.
        print(f"    StatiCrypt stopped (exit {result.returncode}), so this page wasn't encrypted. "
              "To see its own message, run with STATICRYPT_DEBUG=1 on your own terminal.", file=sys.stderr)
        if os.environ.get("STATICRYPT_DEBUG") and sys.stderr.isatty() and not IN_CI:
            print(result.stderr.replace(password, "<password>"), file=sys.stderr)
        return False
    out = output_dir / src.name
    return out.exists() and is_staticrypt_output(out)


# ---------------------------------------------------------------- main
def resolve_mode(args) -> tuple:
    """Return (mode, secret). Never prints either value."""
    override = os.environ.get("ENCRYPT_PASSWORD", "").strip()
    master = os.environ.get("ENCRYPT_SECRET", "").strip()
    if getattr(args, "derived", False):
        if not ALLOW_DERIVED:
            sys.exit("ERROR: --derived is not available in this repo (single portal password only).")
        if not master:
            sys.exit("ERROR: --derived needs ENCRYPT_SECRET in .env (your password manager holds it).")
        return "derived", master
    if DEFAULT_MODE == "shared":
        if not override:
            sys.exit("ERROR: ENCRYPT_PASSWORD (the shared password for this repo) is not set. Add it to .env from your password manager"
                     + (", or pass --derived for a page that deliberately needs its own password." if ALLOW_DERIVED else "."))
        return "shared", override
    if override:
        return "shared", override
    if not master:
        sys.exit("ENCRYPT_SECRET is not set, so there's no master secret yet and nothing was encrypted. Ask Claude to set "
                 "up encryption in this folder and say yes to creating one (it's saved in .env and never shown).")
    return "derived", master


def main():
    parser = argparse.ArgumentParser(description="Encrypt public-encrypted/ into the Pages release folder and check every output.")
    parser.add_argument("--show", action="store_true", help="report mode and counts; with --reveal on a terminal, the password table")
    parser.add_argument("--reveal", action="store_true", help="with --show: print the per-file passwords (TTY only, refused in CI)")
    parser.add_argument("--skip-unchanged", action="store_true", help="skip pages whose fingerprint (source+password+template+salt+tool) is current")
    parser.add_argument("--file", metavar="FILENAME", help="one file only (relative path or basename)")
    parser.add_argument("--count", action="store_true", help="print only the number of pages a run would encrypt, then stop")
    parser.add_argument("--new-password", metavar="PAGE", help="give PAGE (path under public-encrypted/) a new password ThoughtfulX<CODE>_<4 random>, save it to .env.page-passwords and copy it to the clipboard; never printed")
    parser.add_argument("--code", metavar="CODE", help="with --new-password: the client code in the password, e.g. NMJ")
    parser.add_argument("--copy", metavar="PAGE", help="copy PAGE's current password to the clipboard; never printed")
    if ALLOW_DERIVED and DEFAULT_MODE == "shared":
        parser.add_argument("--derived", action="store_true", help="give the page(s) a derived per-file password instead of the shared one")
    args = parser.parse_args()
    if args.count:
        if not SOURCE_DIR.exists():
            sys.exit(f"The folder {SOURCE_DIR.name}/ isn't there, so there's nothing to encrypt. Ask Claude to set up encryption in this folder.")
        print(len(select_pages(SOURCE_DIR)))
        return

    if args.new_password:
        rel = args.new_password.strip().lstrip("/")
        if not (SOURCE_DIR / rel).is_file():
            sys.exit(f"I can't find {rel} in {SOURCE_DIR.name}/. Check the path, then run it again.")
        pwd = new_page_password(args.code)
        save_page_password(rel, pwd)
        copy_to_clipboard(pwd)
        print(f"New password for {rel} saved to {PAGE_PASSWORDS_FILE.name} and copied to the clipboard (not printed). "
              "Run `make encrypt-changed` to re-encrypt the page with it.")
        return

    mode, secret = resolve_mode(args)
    if not SOURCE_DIR.exists():
        sys.exit(f"The folder {SOURCE_DIR.name}/ isn't there, so there's nothing to encrypt. Ask Claude to set up encryption in this folder.")

    html_files = select_pages(SOURCE_DIR)
    rel_paths = {f: f.relative_to(SOURCE_DIR).as_posix() for f in html_files}
    if args.file:
        html_files = [f for f in html_files if rel_paths[f] == args.file or f.name == args.file]
        if not html_files:
            sys.exit(f"I can't find {args.file} in {SOURCE_DIR.name}/. Check the name, then run it again.")

    passwords = {rel_paths[f]: (secret if mode == "shared" else derive_password(secret, rel_paths[f])) for f in html_files}
    page_pw = load_page_passwords()
    for rel in passwords:
        if rel in page_pw:
            passwords[rel] = page_pw[rel]

    if args.copy:
        rel = args.copy.strip().lstrip("/")
        if rel not in passwords:
            sys.exit(f"I can't find {rel} in {SOURCE_DIR.name}/. Check the path, then run it again.")
        copy_to_clipboard(passwords[rel])
        print(f"Password for {rel} copied to the clipboard (not printed).")
        return

    if args.show:
        where = "ENCRYPT_PASSWORD in .env (one shared password)" if mode == "shared" else "derived per file from ENCRYPT_SECRET in .env"
        n_own = sum(1 for r in passwords if r in page_pw)
        if n_own:
            where += f"; {n_own} page(s) use their own password from {PAGE_PASSWORDS_FILE.name}"
        print(f"\n{len(html_files)} page(s) under {SOURCE_DIR.relative_to(WORKSPACE)}/ - passwords: {where}.")
        if not args.reveal:
            print("Values are not printed. On a terminal, add --reveal to see the table; the secret itself lives in your password manager.")
            return
        if IN_CI or not sys.stdout.isatty():
            sys.exit("REFUSED: --reveal prints passwords and this is not an interactive terminal (or CI is set).")
        print(f"\n  {'File':<60} Password")
        print(f"  {'-' * 60} {'-' * 24}")
        for rel, pwd in passwords.items():
            print(f"  {rel:<60} {pwd}")
        print("\nShare one password per recipient. Never paste this table into a chat, a doc or a commit.")
        return

    if TEMPLATE.is_symlink() or not TEMPLATE.is_file():
        sys.exit(f"{TEMPLATE.relative_to(WORKSPACE).as_posix()} is missing, so nothing was encrypted (StatiCrypt's own "
                 "page is never used instead). Ask Claude to set up encryption in this folder again.")
    template_bytes = TEMPLATE.read_bytes()
    config_bytes = CONFIG_FILE.read_bytes() if CONFIG_FILE.exists() else b""
    fingerprints = load_fingerprints()

    todo, skipped = [], []
    for src in html_files:
        rel = rel_paths[src]
        out = OUTPUT_DIR / rel
        if is_staticrypt_output(src):
            sys.exit(f"{rel} in {SOURCE_DIR.name}/ is already encrypted, so encrypting it again would wrap it twice. "
                     f"Put the readable page in {SOURCE_DIR.name}/ instead, then run it again.")
        fp = file_fingerprint(src, passwords[rel], template_bytes, config_bytes)
        if args.skip_unchanged and fingerprints.get(rel) == fp and is_staticrypt_output(out):
            skipped.append(rel)
            continue
        todo.append((src, rel, fp))

    print(f"\nEncrypting {len(todo)} page(s) (template: {TEMPLATE.name}), {len(skipped)} unchanged -> {OUTPUT_DIR.relative_to(WORKSPACE)}/")

    failed = []
    for src, rel, fp in todo:
        print(f"  {rel} ...", end=" ", flush=True)
        ok = encrypt_file(src, OUTPUT_DIR / Path(rel).parent, passwords[rel])
        print("done" if ok else "not encrypted")
        if ok:
            fingerprints[rel] = fp
        else:
            failed.append(rel)
            fingerprints.pop(rel, None)
    save_fingerprints(fingerprints)

    if failed:
        print(f"\n{len(failed)} page(s) weren't encrypted: " + ", ".join(failed) + ". Fix the cause above, then run "
              "`make encrypt` again.", file=sys.stderr)
        sys.exit(1)
    print(f"\nDone. {len(todo)} encrypted, {len(skipped)} unchanged; every output checked. "
          f"Passwords: {'ENCRYPT_PASSWORD' if mode == 'shared' else 'derived from ENCRYPT_SECRET'} (never printed; --show --reveal on a terminal).")


if __name__ == "__main__":
    main()
