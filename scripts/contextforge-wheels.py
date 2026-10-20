#!/usr/bin/env python3
"""Compute the wheel set of a ContextForge release for the release lock.

SRS FR-22.18 and FR-22.20: the release lock lists, for each platform of
the managed-process form, every wheel that installs the pinned ContextForge
release with its SHA-256 and its PyPI URL. This script derives the set from
the release's own lock file:

1. it reads pyproject.toml and uv.lock of the release commit from GitHub;
2. `uv export` turns uv.lock into hashed requirements without the
   development dependencies; the release's own wheel from PyPI is added;
3. for each platform, `uv pip compile` evaluates the environment markers
   for CPython 3.12 on that platform, and `pip download --require-hashes
   --only-binary=:all:` picks one wheel per package;
4. each wheel's SHA-256 is computed from the downloaded file and its URL
   is looked up in the PyPI JSON API by file name.

The result replaces the "python" and "wheels" members of the lock file:

    python3 -I scripts/contextforge-wheels.py --lock packaging/contextforge.lock.json

It needs uv, network access and a CPython 3.12 with pip (`uv venv -p 3.12`
provides one; pass it with --pip-python). Windows on arm64 is not a wheel
platform: brotli, cryptography, httptools and jq publish no win_arm64
wheels for CPython 3.12, so the managed process there runs the
windows/amd64 set under an x64 interpreter (docs/contextforge.md).
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

PYTHON = "3.12"

# Platform of the lock -> (uv --python-platform, pip --platform tags).
PLATFORMS = {
    "linux/amd64": ("x86_64-manylinux_2_28", ["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64",
                                              "manylinux_2_5_x86_64", "manylinux1_x86_64", "linux_x86_64"]),
    "linux/arm64": ("aarch64-manylinux_2_28", ["manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64",
                                               "linux_aarch64"]),
    "darwin/arm64": ("aarch64-apple-darwin", ["macosx_14_0_arm64", "macosx_13_0_arm64", "macosx_12_0_arm64", "macosx_11_0_arm64",
                                              "macosx_10_9_universal2", "macosx_10_12_universal2", "macosx_10_13_universal2"]),
    "windows/amd64": ("x86_64-pc-windows-msvc", ["win_amd64"]),
}


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 -- fixed https URLs
        return r.read()


def pypi_files(name, version, cache):
    key = (name.lower(), version)
    if key not in cache:
        d = json.loads(fetch(f"https://pypi.org/pypi/{name}/{version}/json"))
        cache[key] = {u["filename"]: u for u in d["urls"]}
    return cache[key]


def wheel_name_version(fn):
    # name-version(-build)?-python-abi-platform.whl
    parts = fn[:-4].split("-")
    return parts[0], parts[1]


def run(args, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)  # noqa: S603 -- fixed tools
    if r.returncode != 0:
        sys.exit(f"{' '.join(args[:3])} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", required=True, help="lock file to update")
    ap.add_argument("--pip-python", default=os.environ.get("PIP_PYTHON", "python3.12"), help="CPython 3.12 with pip")
    ap.add_argument("--out", help="write the lock here instead of in place")
    a = ap.parse_args()

    with open(a.lock, encoding="utf-8") as f:
        lock = json.load(f)
    cf = lock["contextforge"]
    version = cf["version"].lstrip("v")
    repo = cf["source"]["repository"].removeprefix("https://github.com/")
    commit = cf["source"]["commit"]
    cache = {}

    with tempfile.TemporaryDirectory() as tmp:
        for name in ("pyproject.toml", "uv.lock"):
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(fetch(f"https://raw.githubusercontent.com/{repo}/{commit}/{name}"))
        req = os.path.join(tmp, "req.txt")
        run(["uv", "export", "--directory", tmp, "--frozen", "--no-dev", "--no-emit-project", "--no-header",
             "--format", "requirements-txt", "-o", req])
        own = [u for fn, u in pypi_files("mcp-contextforge-gateway", version, cache).items() if fn.endswith("-py3-none-any.whl")]
        if len(own) != 1:
            sys.exit(f"PyPI has no single universal wheel of mcp-contextforge-gateway {version}")
        with open(req, "a", encoding="utf-8") as f:
            f.write(f"mcp-contextforge-gateway=={version} --hash=sha256:{own[0]['digests']['sha256']}\n")

        wheels = {}
        for plat, (uvplat, tags) in PLATFORMS.items():
            preq = os.path.join(tmp, "req-" + uvplat + ".txt")
            run(["uv", "pip", "compile", "-q", "--no-header", "--python-version", PYTHON, "--python-platform", uvplat,
                 "--no-deps", "--generate-hashes", req, "-o", preq])
            dest = os.path.join(tmp, "w-" + uvplat)
            args = [a.pip_python, "-m", "pip", "download", "-q", "--disable-pip-version-check", "-d", dest,
                    "--only-binary=:all:", "--python-version", PYTHON, "--implementation", "cp",
                    "--abi", "cp312", "--abi", "abi3", "--abi", "none", "--no-deps", "--require-hashes", "-r", preq]
            for t in tags:
                args += ["--platform", t]
            run(args)
            files = []
            for fn in sorted(os.listdir(dest)):
                if not fn.endswith(".whl"):
                    sys.exit(f"{plat}: {fn} is not a wheel")
                with open(os.path.join(dest, fn), "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
                name, ver = wheel_name_version(fn)
                u = pypi_files(name, ver, cache).get(fn)
                if u is None or u["digests"]["sha256"] != sha:
                    sys.exit(f"{plat}: {fn} is not the PyPI file of {name} {ver}")
                files.append({"file": fn, "sha256": sha, "url": u["url"]})
            n = sum(1 for x in files if re.match(r"mcp_contextforge_gateway-", x["file"]))
            if n != 1:
                sys.exit(f"{plat}: {n} ContextForge wheels")
            wheels[plat] = files
            print(f"{plat}: {len(files)} wheels", file=sys.stderr)

    ordered = {}
    for k, v in cf.items():
        if k == "python":
            continue
        if k == "wheels":
            ordered["python"] = PYTHON
            v = wheels
        ordered[k] = v
    lock["contextforge"] = ordered
    out = a.out or a.lock
    with open(out, "w", encoding="utf-8") as f:
        json.dump(lock, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
