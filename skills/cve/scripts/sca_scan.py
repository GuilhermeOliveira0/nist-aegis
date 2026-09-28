#!/usr/bin/env python3
"""Inventário de dependências e consulta de vulnerabilidades por pacote e versão.

Uso:
    python sca_scan.py --raiz <projeto> --saida <projeto>/security-audit/.trabalho/sca.json
    python sca_scan.py --raiz <projeto> --saida <arquivo.json> --db ~/.nvd/nvd.sqlite
    python sca_scan.py --raiz <projeto> --saida <arquivo.json> --offline

Lê os lockfiles do projeto e monta o inventário com nome, versão exata, arquivo e linha,
dependência direta ou transitiva e, no npm, a cadeia até o pacote direto. Consulta o OSV
(api.osv.dev), que casa nome e versão por ecossistema com as faixas nativas do GitHub Advisory
Database, PyPA, Go, RustSec e outras fontes — inclusive CVEs que a NVD não enriqueceu com CPE e
pacotes maliciosos conhecidos (MAL-*). Quando há base local da NVD, completa cada CVE com a nota,
o CWE e a data de entrada no catálogo KEV da CISA.

Privacidade: no modo online, nome e versão de cada pacote vão para api.osv.dev. Pacote npm
resolvido fora do registro público e nome que case --nao-enviar ficam de fora; com --offline
nada sai da máquina e só o inventário é produzido.

Só biblioteca padrão; Python 3.11 ou superior (tomllib). Nunca executa nada do projeto e nunca
imprime valor de token encontrado em configuração de gerenciador.

Códigos de saída: 0 inventário gravado (mesmo com vulnerabilidades ou falha na consulta, que
fica registrada no JSON), 2 argumento inválido, 3 erro de execução.
"""

import argparse
import concurrent.futures
import json
import math
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nvd_common as nc  # noqa: E402

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/%s"
BATCH_SIZE = 1000
DETAIL_WORKERS = 8

EXCLUDED_DIRS = {
    "node_modules", ".venv", "venv", "vendor", "dist", "build", ".git", "target", "out",
    ".next", "coverage", "bin", "obj", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    "security-audit",
}
PUBLIC_NPM_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}
PUBLIC_PYPI_HOSTS = {"pypi.org", "files.pythonhosted.org"}

LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm", "bun.lock": "npm", "bun.lockb": "npm",
    "poetry.lock": "PyPI", "uv.lock": "PyPI", "Pipfile.lock": "PyPI", "pdm.lock": "PyPI",
    "go.mod": "Go", "Cargo.lock": "crates.io", "composer.lock": "Packagist",
    "Gemfile.lock": "RubyGems", "packages.lock.json": "NuGet", "gradle.lockfile": "Maven",
}
MANIFESTS = {
    "package.json": ("npm", ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                             "pnpm-lock.yaml", "bun.lock", "bun.lockb")),
    "Pipfile": ("PyPI", ("Pipfile.lock",)),
    "composer.json": ("Packagist", ("composer.lock",)),
    "Gemfile": ("RubyGems", ("Gemfile.lock",)),
    "Cargo.toml": ("crates.io", ("Cargo.lock",)),
}
UNSUPPORTED = {
    "bun.lockb": "formato binário",
    "bun.lock": "formato do Bun ainda não suportado",
    "pdm.lock": "formato do PDM ainda não suportado",
    "pom.xml": "Maven sem lockfile: a versão transitiva só existe depois da resolução",
    "build.gradle": "Gradle sem gradle.lockfile: a versão transitiva só existe depois da resolução",
    "build.gradle.kts": "Gradle sem gradle.lockfile: a versão transitiva só existe depois da resolução",
}


class ScanError(RuntimeError):
    pass


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(root, path):
    return os.path.relpath(path, root).replace("\\", "/")


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def host_of(url):
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------- descoberta

def discover(root, extra_excluded=()):
    excluded = EXCLUDED_DIRS | set(extra_excluded)
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded)
        for name in sorted(filenames):
            if name in LOCKFILES or name in MANIFESTS or name in UNSUPPORTED or name == ".npmrc" \
                    or re.match(r"^requirements.*\.txt$", name) or name == "pyproject.toml":
                found.append(os.path.join(dirpath, name))
    return found


def _pkg(eco, name, version, arquivo, linha, direto=None, dev=None, cadeia=None, origem=None,
         licenca=None, script_instalacao=None):
    return {
        "ecossistema": eco, "nome": name, "versao": version, "arquivo": arquivo, "linha": linha,
        "direto": direto, "dev": dev, "cadeia": cadeia, "origem": origem, "licenca": licenca,
        "script_instalacao": script_instalacao,
    }


# ---------------------------------------------------------------- npm

def _npm_resolve(packages, from_path, dep):
    base = from_path
    while True:
        cand = (base + "/node_modules/" + dep) if base else ("node_modules/" + dep)
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def _npm_chains(packages, root_deps):
    chains = {}
    queue = []
    for dep in root_deps:
        path = _npm_resolve(packages, "", dep)
        if path and path not in chains:
            chains[path] = [dep]
            queue.append(path)
    while queue:
        path = queue.pop(0)
        info = packages.get(path) or {}
        deps = dict(info.get("dependencies") or {})
        deps.update(info.get("optionalDependencies") or {})
        for dep in deps:
            child = _npm_resolve(packages, path, dep)
            if child and child not in chains:
                chains[child] = chains[path] + [dep]
                queue.append(child)
    return chains


def parse_package_lock(root, path):
    text = read_text(path)
    data = json.loads(text)
    arquivo = rel(root, path)
    lines = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*"(node_modules/[^"]+)"\s*:', line)
        if m and m.group(1) not in lines:
            lines[m.group(1)] = i
    out = []
    packages = data.get("packages")
    if packages:
        root_info = packages.get("") or {}
        prod = set(root_info.get("dependencies") or {}) | set(root_info.get("optionalDependencies") or {})
        dev_direct = set(root_info.get("devDependencies") or {})
        chains = _npm_chains(packages, list(prod) + list(dev_direct))
        for key, info in packages.items():
            if not key or info.get("link") or not info.get("version"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            top = key.count("node_modules/") == 1 and key.startswith("node_modules/")
            out.append(_pkg(
                "npm", name, info["version"], arquivo, lines.get(key),
                direto=bool(top and (name in prod or name in dev_direct)),
                dev=bool(info.get("dev") or info.get("devOptional")),
                cadeia=chains.get(key), origem=info.get("resolved"), licenca=info.get("license"),
                script_instalacao=bool(info.get("hasInstallScript")) or None,
            ))
        return out

    # lockfile v1: árvore aninhada em "dependencies"
    def walk(deps, chain):
        for name, info in (deps or {}).items():
            if not isinstance(info, dict) or not info.get("version"):
                continue
            version = info["version"]
            if re.match(r"^(git\+|https?:|file:|github:)", version):
                origem, version = version, None
            else:
                origem = info.get("resolved")
            if version:
                out.append(_pkg("npm", name, version, arquivo, None, direto=not chain,
                                dev=bool(info.get("dev")), cadeia=chain + [name], origem=origem))
            walk(info.get("dependencies"), chain + [name])
    walk(data.get("dependencies"), [])
    return out


def parse_yarn_lock(root, path):
    text = read_text(path)
    arquivo = rel(root, path)
    out = []
    berry = "__metadata:" in text
    header = None
    header_line = None
    for i, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            header, header_line = line.rstrip()[:-1], i
            continue
        if header is None:
            continue
        if berry:
            m = re.match(r'^\s+resolution:\s+"?(.+?)@npm:([^"\s]+)"?\s*$', line)
            if m:
                out.append(_pkg("npm", m.group(1), m.group(2), arquivo, header_line))
                header = None
        else:
            m = re.match(r'^\s+version\s+"?([^"\s]+)"?\s*$', line)
            if m:
                spec = header.split(",")[0].strip().strip('"')
                name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
                out.append(_pkg("npm", name, m.group(1), arquivo, header_line))
                header = None
    return _dedup(out)


def parse_pnpm_lock(root, path):
    text = read_text(path)
    arquivo = rel(root, path)
    out = []
    section = None
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^[a-zA-Z]", line):
            section = line.split(":", 1)[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        m = re.match(r"^  '?/?((?:@[^@/\s']+/)?[^@/\s']+)@([0-9][^\s:()']*)", line)
        if m:
            out.append(_pkg("npm", m.group(1), m.group(2), arquivo, i))
    return _dedup(out)


# ---------------------------------------------------------------- Python

_REQ_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;,#\\]+)\s*(?:;.*)?$")
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_requirements(root, path, extras):
    arquivo = rel(root, path)
    out = []
    for i, raw in enumerate(read_text(path).splitlines(), 1):
        line = raw.split(" #", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            editavel = re.match(r"^(?:-e|--editable)[=\s]+(\S+)", line)
            if editavel:
                extras["fonte_fora_do_registro"].append({
                    "arquivo": arquivo, "linha": i, "nome": None,
                    "origem": "instalação editável ou de repositório (%s)" % (
                        host_of(editavel.group(1)) or "caminho local")})
                continue
            m = re.match(r"^--?(?:i|index-url|extra-index-url)[=\s]+(\S+)", line)
            if m and host_of(m.group(1)) not in PUBLIC_PYPI_HOSTS:
                extras["fonte_fora_do_registro"].append(
                    {"arquivo": arquivo, "linha": i, "nome": None, "origem": "índice " + host_of(m.group(1))})
            continue
        if "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")) or " @ " in line:
            nome = _REQ_NAME.match(line)
            extras["fonte_fora_do_registro"].append({
                "arquivo": arquivo, "linha": i, "nome": nome.group(1) if nome else None,
                "origem": "URL ou repositório direto"})
            continue
        m = _REQ_PIN.match(line)
        if m:
            out.append(_pkg("PyPI", pep503(m.group(1)), m.group(3), arquivo, i))
            continue
        nome = _REQ_NAME.match(line)
        if nome:
            extras["sem_pin"].append({"arquivo": arquivo, "linha": i, "nome": pep503(nome.group(1)),
                                      "especificacao": line, "motivo": "sem versão exata (==)"})
    return out


def parse_pipfile_lock(root, path, extras):
    arquivo = rel(root, path)
    data = json.loads(read_text(path))
    for source in (data.get("_meta") or {}).get("sources") or []:
        if host_of(source.get("url", "")) not in PUBLIC_PYPI_HOSTS:
            extras["fonte_fora_do_registro"].append(
                {"arquivo": arquivo, "linha": None, "nome": None, "origem": "índice " + host_of(source.get("url", ""))})
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            version = (info.get("version") or "").lstrip("=")
            if version:
                out.append(_pkg("PyPI", pep503(name), version, arquivo, None, dev=dev))
    return out


def _toml(path):
    if tomllib is None:
        raise ScanError("Python 3.11 ou superior é necessário para ler %s" % os.path.basename(path))
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _toml_lines(text, key="name"):
    lines = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^%s\s*=\s*"([^"]+)"' % key, line)
        if m:
            lines.setdefault(m.group(1).lower(), i)
    return lines


def parse_poetry_or_uv(root, path, extras):
    arquivo = rel(root, path)
    text = read_text(path)
    data = _toml(path)
    lines = _toml_lines(text)
    out = []
    for pkg in data.get("package") or []:
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source") or {}
        if not name or not version:
            continue
        if isinstance(source, dict) and (source.get("editable") or source.get("virtual") or source.get("directory")):
            continue  # o próprio projeto ou um caminho local
        if isinstance(source, dict) and (source.get("git") or source.get("url") or source.get("type") in ("git", "url", "file")):
            extras["fonte_fora_do_registro"].append({
                "arquivo": arquivo, "linha": lines.get(name.lower()), "nome": pep503(name),
                "origem": "repositório ou URL direta"})
        registry = source.get("registry") or source.get("url") if isinstance(source, dict) else None
        if registry and host_of(registry) not in PUBLIC_PYPI_HOSTS | {""} and source.get("type") not in ("git",):
            extras["fonte_fora_do_registro"].append({
                "arquivo": arquivo, "linha": lines.get(name.lower()), "nome": pep503(name),
                "origem": "índice " + host_of(registry)})
        dev = pkg.get("category") == "dev" if "category" in pkg else None
        out.append(_pkg("PyPI", pep503(name), version, arquivo, lines.get(name.lower()), dev=dev))
    return out


# ---------------------------------------------------------------- Go, Rust, PHP, Ruby, .NET, Gradle

def parse_go_mod(root, path, extras):
    arquivo = rel(root, path)
    out = []
    in_block = False
    for i, raw in enumerate(read_text(path).splitlines(), 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = None
        if in_block:
            m = re.match(r"^(\S+)\s+(v\S+)(.*)$", line)
        elif line.startswith("require "):
            m = re.match(r"^require\s+(\S+)\s+(v\S+)(.*)$", line)
        if m:
            out.append(_pkg("Go", m.group(1), m.group(2).lstrip("v"), arquivo, i,
                            direto="// indirect" not in m.group(3)))
            continue
        g = re.match(r"^go\s+(\d+\.\d+\.\d+)\s*$", line) or re.match(r"^toolchain\s+go(\d+\.\d+\.\d+)\s*$", line)
        if g:
            out.append(_pkg("Go", "stdlib", g.group(1), arquivo, i, direto=True))
        r = re.match(r"^replace\s+\S+.*=>\s+(\.{1,2}/\S*|/\S*)", line)
        if r:
            extras["fonte_fora_do_registro"].append(
                {"arquivo": arquivo, "linha": i, "nome": None, "origem": "replace para caminho local " + r.group(1)})
    return _dedup(out)


def parse_cargo_lock(root, path, extras):
    arquivo = rel(root, path)
    text = read_text(path)
    lines = _toml_lines(text)
    out = []
    for pkg in _toml(path).get("package") or []:
        source = pkg.get("source")
        if not source:
            continue  # membro do workspace
        if not source.startswith("registry+https://github.com/rust-lang/crates.io-index") \
                and not source.startswith("sparse+https://index.crates.io"):
            extras["fonte_fora_do_registro"].append({
                "arquivo": arquivo, "linha": lines.get(pkg.get("name", "").lower()),
                "nome": pkg.get("name"), "origem": source.split("#")[0]})
        out.append(_pkg("crates.io", pkg["name"], pkg["version"], arquivo, lines.get(pkg["name"].lower())))
    return out


def parse_composer_lock(root, path, extras):
    arquivo = rel(root, path)
    text = read_text(path)
    data = json.loads(text)
    lines = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*"name":\s*"([^"]+)"', line)
        if m:
            lines.setdefault(m.group(1).lower(), i)
    out = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for pkg in data.get(section) or []:
            name = pkg.get("name")
            version = (pkg.get("version") or "").lstrip("v")
            if not name or not version or version.startswith("dev-"):
                continue
            origem = ((pkg.get("dist") or {}).get("url")) or ((pkg.get("source") or {}).get("url"))
            licenca = pkg.get("license")
            out.append(_pkg("Packagist", name, version, arquivo, lines.get(name.lower()), dev=dev,
                            origem=origem, licenca=", ".join(licenca) if isinstance(licenca, list) else licenca))
    return out


def parse_gemfile_lock(root, path, extras):
    arquivo = rel(root, path)
    out = []
    section = None
    direct = set()
    lines = read_text(path).splitlines()
    for raw in lines:
        if raw and not raw.startswith(" "):
            section = raw.strip()
        elif section == "DEPENDENCIES":
            m = re.match(r"^  ([A-Za-z0-9_.-]+)", raw)
            if m:
                direct.add(m.group(1))
    section = None
    for i, raw in enumerate(lines, 1):
        if raw and not raw.startswith(" "):
            section = raw.strip()
            continue
        if section in ("GIT", "PATH") and raw.strip().startswith("remote:"):
            extras["fonte_fora_do_registro"].append(
                {"arquivo": arquivo, "linha": i, "nome": None, "origem": section + " " + raw.split(":", 1)[1].strip()})
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", raw)
        if m and section == "GEM":
            version = re.split(r"-(?=(?:x86|x64|arm|aarch|java|universal|mingw|mswin))", m.group(2))[0]
            out.append(_pkg("RubyGems", m.group(1), version, arquivo, i, direto=m.group(1) in direct))
    return out


def parse_nuget_lock(root, path, extras):
    arquivo = rel(root, path)
    out = []
    for deps in (json.loads(read_text(path)).get("dependencies") or {}).values():
        for name, info in (deps or {}).items():
            if info.get("type") == "Project" or not info.get("resolved"):
                continue
            out.append(_pkg("NuGet", name, info["resolved"], arquivo, None, direto=info.get("type") == "Direct"))
    return _dedup(out)


def parse_gradle_lockfile(root, path, extras):
    arquivo = rel(root, path)
    out = []
    for i, line in enumerate(read_text(path).splitlines(), 1):
        m = re.match(r"^([^#:\s]+):([^:\s]+):([^=\s]+)=", line.strip())
        if m:
            out.append(_pkg("Maven", "%s:%s" % (m.group(1), m.group(2)), m.group(3), arquivo, i))
    return out


def _dedup(pkgs):
    seen = set()
    out = []
    for p in pkgs:
        key = (p["ecossistema"], p["nome"], p["versao"], p["arquivo"])
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


PARSERS = {
    "package-lock.json": lambda r, p, e: parse_package_lock(r, p),
    "npm-shrinkwrap.json": lambda r, p, e: parse_package_lock(r, p),
    "yarn.lock": lambda r, p, e: parse_yarn_lock(r, p),
    "pnpm-lock.yaml": lambda r, p, e: parse_pnpm_lock(r, p),
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_or_uv,
    "uv.lock": parse_poetry_or_uv,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "packages.lock.json": parse_nuget_lock,
    "gradle.lockfile": parse_gradle_lockfile,
}


# ---------------------------------------------------------------- manifestos npm e .npmrc

_NPM_OPEN = re.compile(r"^\s*(\*|x|latest|>=?\s*[\d.]+\s*|)\s*$", re.IGNORECASE)
_NPM_SOURCE = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:)|^[\w.-]+/[\w.-]+(#.*)?$")


def check_package_json(root, path, has_lock, extras):
    arquivo = rel(root, path)
    text = read_text(path)
    try:
        data = json.loads(text)
    except ValueError:
        return
    lines = text.splitlines()
    for section in ("dependencies", "optionalDependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            linha = next((i for i, l in enumerate(lines, 1) if re.search(r'"%s"\s*:' % re.escape(name), l)), None)
            if _NPM_SOURCE.match(spec):
                if not re.search(r"#[0-9a-f]{40}$", spec):
                    extras["fonte_fora_do_registro"].append({
                        "arquivo": arquivo, "linha": linha, "nome": name,
                        "origem": "git, URL ou caminho local sem commit fixado"})
            elif _NPM_OPEN.match(spec) or (">" in spec and "<" not in spec):
                extras["sem_pin"].append({"arquivo": arquivo, "linha": linha, "nome": name,
                                          "especificacao": spec, "motivo": "faixa aberta"})
            elif not has_lock and re.match(r"^[\^~]", spec):
                extras["sem_pin"].append({"arquivo": arquivo, "linha": linha, "nome": name,
                                          "especificacao": spec, "motivo": "faixa sem lockfile que a fixe"})


def check_npmrc(root, path, extras):
    """Registra só a URL de registro alternativo. Nunca lê nem devolve token."""
    arquivo = rel(root, path)
    for i, line in enumerate(read_text(path).splitlines(), 1):
        m = re.match(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)", line)
        if m and host_of(m.group(2)) not in PUBLIC_NPM_HOSTS:
            extras["fonte_fora_do_registro"].append({
                "arquivo": arquivo, "linha": i, "nome": (m.group(1) or "").rstrip(":") or None,
                "origem": "registro " + host_of(m.group(2))})


def _has_lock_up(root, directory, candidates):
    current = os.path.abspath(directory)
    root = os.path.abspath(root)
    while True:
        if any(os.path.exists(os.path.join(current, c)) for c in candidates):
            return True
        if current == root or os.path.dirname(current) == current:
            return False
        current = os.path.dirname(current)


# ---------------------------------------------------------------- OSV

def http_json(url, body=None, timeout=60, retries=4):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"User-Agent": "nist-aegis/1.1", "Content-Type": "application/json"}
    delay = 2.0
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise ScanError("OSV respondeu HTTP %d" % exc.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise ScanError("falha de rede ao consultar o OSV: %s" % type(exc).__name__)
        except ValueError:
            raise ScanError("o OSV devolveu uma resposta que não é JSON válido")
    raise ScanError("consulta ao OSV falhou após %d tentativas" % retries)


def osv_query(queries):
    """Devolve, para cada consulta, a lista de IDs de vulnerabilidade."""
    ids = [[] for _ in queries]
    for start in range(0, len(queries), BATCH_SIZE):
        chunk = queries[start:start + BATCH_SIZE]
        payload = http_json(OSV_BATCH, {"queries": chunk}) or {}
        for offset, result in enumerate(payload.get("results") or []):
            index = start + offset
            ids[index].extend(v["id"] for v in result.get("vulns") or [] if v.get("id"))
            token = result.get("next_page_token")
            while token:
                extra = http_json(OSV_BATCH, {"queries": [dict(chunk[offset], page_token=token)]}) or {}
                page = (extra.get("results") or [{}])[0]
                ids[index].extend(v["id"] for v in page.get("vulns") or [] if v.get("id"))
                token = page.get("next_page_token")
    return ids


def osv_details(vuln_ids):
    """Devolve (detalhes por ID, erros). Falha num ID não derruba os outros."""
    details = {}
    erros = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
        futures = {pool.submit(http_json, OSV_VULN % urllib.parse.quote(v)): v for v in vuln_ids}
        for future in concurrent.futures.as_completed(futures):
            vid = futures[future]
            try:
                details[vid] = future.result()
            except ScanError as exc:
                erros.append("%s: detalhe não obtido (%s)" % (vid, exc))
    return details, erros


# ---------------------------------------------------------------- CVSS 3.x

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value):
    inteiro = int(round(value * 100000))
    if inteiro % 10000 == 0:
        return inteiro / 100000.0
    return (math.floor(inteiro / 10000) + 1) / 10.0


def cvss3_score(vector):
    """Nota base CVSS 3.0/3.1 a partir do vetor; None se o vetor não for 3.x válido."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploitability = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    base = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(base, 10))


def severity_name(score):
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------- enriquecimento pela base local

class NvdLocal:
    def __init__(self, path):
        self.conn = None
        self.info = None
        if not path:
            return
        try:
            self.conn = nc.connect(path, create=False, readonly=True)
        except (FileNotFoundError, sqlite3.Error):
            self.info = {"caminho": nc.db_path(path), "estado": "ausente"}
            return
        cols = nc.table_columns(self.conn, "cves")
        self.kev_col = "kev_added" if "kev_added" in cols else "json_extract(raw, '$.cisaExploitAdd')"
        self.source_col = "cvss_source" if "cvss_source" in cols else "NULL"
        self.info = {
            "caminho": nc.db_path(path),
            "estado": "disponível",
            "last_sync": nc.meta_get(self.conn, "last_sync"),
            "completa": nc.meta_get(self.conn, "complete") == "1",
            "versao_dados": int(nc.meta_get(self.conn, "data_version", "1") or 1),
        }

    def lookup(self, cve_id):
        if not self.conn:
            return None
        try:
            row = self.conn.execute(
                "SELECT base_score, base_severity, cvss_version, vector_string, cwes, severity_rank,"
                " vuln_status, %s AS fonte, %s AS kev FROM cves WHERE cve_id = ?"
                % (self.source_col, self.kev_col), (cve_id,)).fetchone()
        except sqlite3.Error:
            return None
        return dict(row) if row else None


# ---------------------------------------------------------------- montagem do resultado

def _fixed_versions(vuln, eco, name):
    fixed = []
    last = []
    alvo = pep503(name) if eco == "PyPI" else name.lower()
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        nome = pep503(pkg.get("name", "")) if eco == "PyPI" else (pkg.get("name") or "").lower()
        if pkg.get("ecosystem") != eco or nome != alvo:
            continue
        for rng in aff.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed") and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
                if event.get("last_affected") and event["last_affected"] not in last:
                    last.append(event["last_affected"])
    return fixed, last


def summarize_vuln(vuln, eco, name, nvd):
    ident = vuln.get("id")
    aliases = [a for a in vuln.get("aliases") or [] if a != ident]
    todos = [ident] + aliases
    cves = sorted({a for a in todos if a.startswith("CVE-")})
    db_spec = vuln.get("database_specific") or {}
    vector3 = next((s.get("score") for s in vuln.get("severity") or [] if s.get("type") == "CVSS_V3"), None)
    vector4 = next((s.get("score") for s in vuln.get("severity") or [] if s.get("type") == "CVSS_V4"), None)

    severidade = None
    for cve in cves:
        info = nvd.lookup(cve)
        if info and info.get("base_score") is not None:
            fonte = "NVD local" + (" (%s)" % info["fonte"] if info.get("fonte") else "")
            severidade = {"fonte": fonte, "cve": cve,
                          "versao_cvss": info["cvss_version"], "nota": info["base_score"],
                          "nivel": info["base_severity"], "vetor": info["vector_string"]}
            break
    if severidade is None and vector3:
        nota = cvss3_score(vector3)
        severidade = {"fonte": "OSV (CVSS 3.x calculado do vetor)", "versao_cvss": vector3.split("/")[0][5:],
                      "nota": nota, "nivel": severity_name(nota), "vetor": vector3}
    if severidade is None and (db_spec.get("severity") or vector4):
        nivel = (db_spec.get("severity") or "").upper().replace("MODERATE", "MEDIUM") or None
        severidade = {"fonte": "OSV (%s)" % ("nível do GHSA" if nivel else "só vetor CVSS 4.0"),
                      "versao_cvss": "4.0" if vector4 else None, "nota": None, "nivel": nivel, "vetor": vector4}

    kev = None
    cwe = list(db_spec.get("cwe_ids") or [])
    for cve in cves:
        info = nvd.lookup(cve)
        if info:
            kev = kev or info.get("kev")
            for c in (info.get("cwes") or "").split(","):
                if c and c not in cwe:
                    cwe.append(c)
    fixed, last = _fixed_versions(vuln, eco, name)
    return {
        "id": ident,
        "aliases": aliases,
        "cve": cves,
        "resumo": (vuln.get("summary") or (vuln.get("details") or "")[:200]).strip(),
        "severidade": severidade,
        "cwe": cwe,
        "kev": kev,
        "corrigido_em": fixed,
        "ultima_afetada": last,
        "malicioso": ident.startswith("MAL-"),
        "referencia": "https://osv.dev/vulnerability/%s" % ident,
    }


def private_reason(pkg, never_send):
    for pattern in never_send:
        if pattern.search(pkg["nome"]):
            return "nome casa --nao-enviar"
    origem = pkg.get("origem") or ""
    if pkg["ecossistema"] == "npm" and origem.startswith("http") and host_of(origem) not in PUBLIC_NPM_HOSTS:
        return "resolvido fora do registro público (%s)" % host_of(origem)
    if pkg["ecossistema"] == "npm" and origem and not origem.startswith("http"):
        return "origem não é o registro público"
    return None


def scan(root, db=None, offline=False, extra_excluded=(), never_send=(), max_pacotes=20000):
    if not os.path.isdir(root):
        raise ScanError("raiz não encontrada: %s" % root)
    extras = {"sem_pin": [], "fonte_fora_do_registro": []}
    arquivos = []
    nao_suportados = []
    erros = []
    pacotes = []
    lock_names = set(LOCKFILES) | {"package-lock.json"}
    for path in discover(root, extra_excluded):
        name = os.path.basename(path)
        arquivo = rel(root, path)
        if name == ".npmrc":
            check_npmrc(root, path, extras)
            continue
        if name in UNSUPPORTED:
            nao_suportados.append({"arquivo": arquivo, "motivo": UNSUPPORTED[name]})
            continue
        if name in MANIFESTS:
            eco, locks = MANIFESTS[name]
            has_lock = _has_lock_up(root, os.path.dirname(path), locks)
            if name == "package.json":
                check_package_json(root, path, has_lock, extras)
            if not has_lock:
                arquivos.append({"arquivo": arquivo, "tipo": "manifesto", "gerenciador": eco,
                                 "lockfile": "ausente"})
            continue
        if name == "pyproject.toml":
            continue
        parser = PARSERS.get(name)
        if name.startswith("requirements") and name.endswith(".txt"):
            parser = parse_requirements
        if parser is None:
            continue
        try:
            found = parser(root, path, extras)
        except (ValueError, KeyError, ScanError) as exc:
            erros.append("%s: não foi possível ler (%s)" % (arquivo, exc))
            continue
        pacotes.extend(found)
        arquivos.append({"arquivo": arquivo, "tipo": "lockfile" if name in lock_names else "requisitos",
                         "gerenciador": LOCKFILES.get(name, "PyPI"), "pacotes": len(found)})
        if name == "pnpm-lock.yaml":
            erros.append("%s: leitura simplificada das chaves de pacote, sem dependência direta nem cadeia" % arquivo)

    pacotes = _dedup(pacotes)
    nvd = NvdLocal(db)
    consulta = {"fonte": "api.osv.dev", "status": "desligada" if offline else "ok",
                "pacotes_enviados": 0, "nao_enviados": [], "erros": []}
    vulneraveis = []
    if offline:
        consulta["fonte"] = "desligada (--offline): nada saiu da máquina"
    else:
        unicos = {}
        for pkg in pacotes:
            motivo = private_reason(pkg, never_send)
            if motivo:
                consulta["nao_enviados"].append({"nome": pkg["nome"], "ecossistema": pkg["ecossistema"], "motivo": motivo})
                continue
            unicos.setdefault((pkg["ecossistema"], pkg["nome"], pkg["versao"]), []).append(pkg)
        chaves = list(unicos)[:max_pacotes]
        if len(unicos) > max_pacotes:
            consulta["erros"].append("inventário com %d pacotes; consultados só os primeiros %d (--max-pacotes)"
                                     % (len(unicos), max_pacotes))
        queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in chaves]
        try:
            ids = osv_query(queries) if queries else []
            consulta["pacotes_enviados"] = len(queries)
            todos_ids = sorted({i for lista in ids for i in lista})
            detalhes, erros_detalhe = osv_details(todos_ids) if todos_ids else ({}, [])
            if erros_detalhe:
                consulta["status"] = "parcial"
                consulta["erros"].extend(erros_detalhe)
        except ScanError as exc:
            consulta["status"] = "falhou"
            consulta["erros"].append(str(exc))
            ids, detalhes = [], {}
        for chave, lista_ids in zip(chaves, ids):
            eco, nome, _ = chave
            vulns = []
            for vid in lista_ids:
                vuln = detalhes.get(vid)
                if not vuln or vuln.get("withdrawn"):
                    continue
                vulns.append(summarize_vuln(vuln, eco, nome, nvd))
            if vulns:
                for pkg in unicos[chave]:
                    vulneraveis.append(dict(pkg, vulnerabilidades=vulns))

    por_eco = {}
    for pkg in pacotes:
        por_eco[pkg["ecossistema"]] = por_eco.get(pkg["ecossistema"], 0) + 1
    limites = [
        "Inventário só dos lockfiles e manifestos listados em `arquivos`; dependência instalada fora deles não aparece.",
        "A consulta casa nome e versão exata; alcançabilidade do código vulnerável não é avaliada aqui.",
    ]
    if nao_suportados:
        limites.append("Arquivos em `nao_suportados` não entraram no inventário.")
    return {
        "ferramenta": "sca_scan",
        "versao": 1,
        "gerado_em": now_iso(),
        "raiz": os.path.abspath(root),
        "consulta": consulta,
        "base_nvd": nvd.info,
        "arquivos": arquivos,
        "nao_suportados": nao_suportados,
        "inventario": {"total": len(pacotes), "por_ecossistema": por_eco},
        "vulneraveis": vulneraveis,
        "maliciosos": [p for p in vulneraveis if any(v["malicioso"] for v in p["vulnerabilidades"])],
        "sem_lockfile": [a for a in arquivos if a.get("lockfile") == "ausente"],
        "sem_pin": extras["sem_pin"],
        "fonte_fora_do_registro": extras["fonte_fora_do_registro"],
        "erros": erros,
        "limites": limites,
    }


def build_parser():
    parser = argparse.ArgumentParser(description="Inventário de dependências e consulta de vulnerabilidades.")
    parser.add_argument("--raiz", required=True, help="raiz do projeto auditado")
    parser.add_argument("--saida", required=True, help="arquivo JSON de saída")
    parser.add_argument("--db", help="base local da NVD para completar nota, CWE e KEV")
    parser.add_argument("--offline", action="store_true", help="não consulta o OSV; só o inventário")
    parser.add_argument("--excluir", action="append", default=[], help="diretório a excluir (repetível)")
    parser.add_argument("--nao-enviar", action="append", default=[],
                        help="expressão regular de nome de pacote que nunca vai ao OSV (repetível)")
    parser.add_argument("--max-pacotes", type=nc.positive_int(200000), default=20000,
                        help="teto de pacotes únicos consultados")
    return parser


def main(argv=None):
    nc.configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        never_send = [re.compile(p) for p in args.nao_enviar]
    except re.error as exc:
        parser.error("--nao-enviar inválido: %s" % exc)
    try:
        resultado = scan(args.raiz, db=args.db, offline=args.offline, extra_excluded=args.excluir,
                         never_send=never_send, max_pacotes=args.max_pacotes)
        saida = os.path.abspath(args.saida)
        os.makedirs(os.path.dirname(saida), exist_ok=True)
        with open(saida, "w", encoding="utf-8") as fh:
            json.dump(resultado, fh, ensure_ascii=False, indent=2)
    except (ScanError, OSError) as exc:
        print("ERRO: %s" % exc, file=sys.stderr)
        return nc.EXIT_ERROR
    cves = {c for p in resultado["vulneraveis"] for v in p["vulnerabilidades"] for c in v["cve"]}
    print("sca_scan: %d pacote(s) em %d arquivo(s); %d vulnerável(is), %d CVE(s), %d malicioso(s); "
          "consulta: %s; resultado em %s" % (
              resultado["inventario"]["total"], len(resultado["arquivos"]),
              len(resultado["vulneraveis"]), len(cves), len(resultado["maliciosos"]),
              resultado["consulta"]["status"], saida))
    return nc.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
