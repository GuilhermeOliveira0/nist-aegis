#!/usr/bin/env python3
"""Inventário determinístico do projeto para a auditoria NIST.

Uso:
    python inventario.py --raiz <projeto> --saida <projeto>/security-audit/.trabalho/inventario.json
    python inventario.py --raiz <projeto> --saida <arquivo.json> --diff main

Conta os arquivos elegíveis (fora dos diretórios excluídos, sem binário, mídia nem lockfile),
lista os versionados no git, os manifestos, a infraestrutura e os pipelines, e procura segredos
com expressões de alta precisão em todos os arquivos de texto — inclusive `.env` e
documentação. O valor de um segredo nunca sai do script: o JSON traz tipo, arquivo, linha e uma
máscara com, no máximo, o prefixo público do provedor e o comprimento.

Também aponta configuração de agente de IA dentro do repositório (`.claude/`, `.mcp.json`,
`CLAUDE.md`, `AGENTS.md`, regras de Cursor e Copilot) e caractere Unicode invisível nesses
arquivos, que o Claude Code carrega como instrução quando a pasta é confiada.

O git roda endurecido para repositório não confiável: executável resolvido fora da raiz, sem
fsmonitor, sem diff externo, sem textconv, sem pager, sem regravar o índice e sem nenhum acesso
a remote (nem o fetch preguiçoso de partial clone). Link simbólico não é seguido. Nunca executa
nada do projeto.

Só biblioteca padrão. Códigos de saída: 0 inventário gravado, 2 argumento inválido, 3 erro.
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone

EXCLUDED_DIRS = {
    "node_modules", ".venv", "venv", "vendor", "dist", "build", ".git", "target",
    "out", ".next", ".nuxt", "coverage", "bin", "obj", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".gradle", ".terraform", "security-audit",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".tif", ".tiff", ".psd",
    ".mp3", ".mp4", ".wav", ".ogg", ".mov", ".avi", ".mkv", ".webm", ".flac",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear",
    ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj", ".class", ".pyc", ".pyo", ".wasm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".sqlite", ".db", ".bin", ".dat",
    ".lockb", ".map",
}
LOCK_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "Cargo.lock", "composer.lock",
    "Gemfile.lock", "packages.lock.json", "gradle.lockfile", "go.sum", "deno.lock", "mix.lock",
    "pubspec.lock", "Package.resolved", "Podfile.lock",
}
MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg",
    "go.mod", "Cargo.toml", "composer.json", "Gemfile", "pom.xml", "build.gradle",
    "build.gradle.kts", "Package.swift", "pubspec.yaml", "mix.exs", "deno.json", "Podfile",
    "CMakeLists.txt", "Makefile", "meson.build", "conanfile.txt", "conanfile.py", "vcpkg.json",
}
LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".go": "Go", ".rs": "Rust",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".vb": "Visual Basic", ".fs": "F#",
    ".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++",
    ".hh": "C++", ".m": "Objective-C", ".mm": "Objective-C", ".swift": "Swift", ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".lua": "Lua", ".pl": "Perl",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".sql": "SQL", ".html": "HTML",
    ".htm": "HTML", ".vue": "Vue", ".svelte": "Svelte", ".tf": "Terraform", ".hcl": "HCL",
    ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".xml": "XML", ".toml": "TOML",
    ".ini": "INI", ".cfg": "INI", ".conf": "Config", ".properties": "Properties",
    ".gradle": "Gradle", ".md": "Markdown", ".rst": "reStructuredText", ".txt": "Texto",
}
C_CPP_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
DOC_EXT = {".md", ".rst", ".txt", ".adoc"}
CI_PATTERNS = (
    re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"), re.compile(r"^\.gitlab-ci\.ya?ml$"),
    re.compile(r"(^|/)azure-pipelines\.ya?ml$"), re.compile(r"(^|/)Jenkinsfile$"),
    re.compile(r"^\.circleci/config\.ya?ml$"), re.compile(r"^bitbucket-pipelines\.ya?ml$"),
    re.compile(r"^\.buildkite/.+\.ya?ml$"),
)
AGENT_CONFIG = (
    re.compile(r"(^|/)CLAUDE(\.local)?\.md$"), re.compile(r"(^|/)AGENTS\.md$"),
    re.compile(r"^\.claude/"), re.compile(r"^\.mcp\.json$"), re.compile(r"(^|/)\.cursorrules$"),
    re.compile(r"^\.cursor/"), re.compile(r"^\.github/copilot-instructions\.md$"),
    re.compile(r"^\.github/instructions/"), re.compile(r"(^|/)\.windsurfrules$"),
    re.compile(r"(^|/)GEMINI\.md$"),
)
HIDDEN_UNICODE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_GENERIC_HITS = 300
BASE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")

# Segredos: (tipo, expressão, prefixo público que a máscara pode mostrar)
SECRET_PATTERNS = (
    ("chave de acesso AWS", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 4),
    ("token do GitHub", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"), 4),
    ("token fino do GitHub", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), 11),
    ("token do GitLab", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), 6),
    ("token do Slack", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 5),
    ("webhook do Slack", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})"), 34),
    ("chave do Stripe", re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"), 8),
    ("chave de API do Google", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 4),
    ("chave da Anthropic", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"), 7),
    ("chave da OpenAI", re.compile(r"\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})\b"), 3),
    ("token do npm", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 4),
    ("chave privada", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"), None),
    ("JWT literal", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), 3),
    ("URL com usuário e senha", re.compile(r"\b([a-z][a-z0-9+.-]{1,20}://[^/\s:@'\"]+:[^/\s@'\"]{3,}@[^\s/'\"]+)"), None),
)
# Identificador que contém a palavra-chave, com prefixo e sufixo de snake_case ou camelCase
# (DB_PASSWORD, JWT_SECRET, SECRET_KEY, apiKey), mas não palavra maior (tokenizer, secretary).
SECRET_KEYWORDS = (r"(?:password|passwd|pwd|senha|secret|token|api[_-]?key|access[_-]?key|"
                   r"private[_-]?key|client[_-]?secret)(?:[_-]?key)?")
GENERIC_SECRET = re.compile(
    r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.-]*?" + SECRET_KEYWORDS + r")(?![A-Za-z0-9])"
    r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
)
# Em arquivo de configuração o valor costuma vir sem aspas (DB_PASSWORD=..., password: ...).
# A chave ocupa a linha desde o início, então `token_ttl: 3600` e chamadas de função não casam.
GENERIC_SECRET_UNQUOTED = re.compile(
    r"(?i)^\s*(?:export\s+)?([A-Za-z0-9_.-]*?" + SECRET_KEYWORDS + r")\s*[:=]\s*"
    r"([^\s\"'#]{8,})\s*(?:#.*)?$"
)
CONFIG_EXT = {".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml"}
PLACEHOLDER = re.compile(
    r"(?i)(changeme|change[_-]?me|your[_-]|<[^>]+>|\$\{[^}]*\}|%\([^)]*\)s|example|exemplo|dummy|"
    r"fake|placeholder|xxxx|\*\*\*\*|redacted|process\.env|os\.environ|getenv|todo|sample)"
)
KNOWN_EXAMPLES = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
TEST_PREFIXES = ("sk_test_", "rk_test_", "pk_test_")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(root, path):
    return os.path.relpath(path, root).replace("\\", "/")


# ---------------------------------------------------------------- git endurecido

def _inside(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    try:
        return os.path.commonpath([os.path.normcase(path), os.path.normcase(root)]) == os.path.normcase(root)
    except ValueError:  # unidades diferentes no Windows
        return False


def git_executable(root):
    """Caminho absoluto do git pelo PATH, recusando entrada relativa e qualquer executável dentro
    da raiz auditada: no Windows a busca padrão começa pela pasta atual, e um `git.exe` plantado
    no repositório rodaria no lugar do verdadeiro."""
    names = ["git"]
    if os.name == "nt":
        exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
        names = ["git" + e.lower() for e in exts]
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if not folder or not os.path.isabs(folder) or _inside(folder, root):
            continue
        for name in names:
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and not _inside(candidate, root):
                return candidate
    raise RuntimeError("git não encontrado no PATH fora da raiz auditada")


def git(root, *args, timeout=60):
    """Roda git sem nada que a configuração do repositório possa transformar em execução."""
    cmd = [
        git_executable(root), "-c", "core.fsmonitor=", "-c", "safe.bareRepository=explicit",
        "-c", "core.quotePath=false", "-c", "diff.external=", "-c", "protocol.allow=never",
        "--no-pager",
    ] + list(args)
    # GIT_NO_LAZY_FETCH: num partial clone, objeto ausente dispararia um fetch pelo remote do
    # repositório — e com ele o core.sshCommand ou o helper que o repositório configurar.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_PAGER="cat",
               GIT_NO_LAZY_FETCH="1")
    result = subprocess.run(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=env)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", "replace").strip()[:300] or "git falhou")
    return [p for p in result.stdout.decode("utf-8", "replace").split("\0") if p]


def git_info(root, diff_base=None):
    info = {"repositorio": os.path.exists(os.path.join(root, ".git")), "versionados": None,
            "erro": None, "diff": None}
    if not info["repositorio"]:
        return info
    try:
        info["versionados"] = sorted(git(root, "ls-files", "-z"))
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        info["erro"] = "git ls-files falhou: %s" % exc
    if diff_base:
        try:
            alterados = git(root, "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv",
                            "%s...HEAD" % diff_base, "--")
            info["diff"] = {"base": diff_base, "alterados": sorted(alterados)}
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            info["diff"] = {"base": diff_base, "alterados": None, "erro": "git diff falhou: %s" % exc}
    return info


# ---------------------------------------------------------------- segredos

def mask(value, prefix_len):
    if prefix_len:
        return "%s…(%d caracteres)" % (value[:prefix_len], len(value))
    return "<valor com %d caracteres>" % len(value)


def classify_example(value):
    if value in KNOWN_EXAMPLES or value.startswith(TEST_PREFIXES):
        return "exemplo ou modo de teste documentado pelo provedor"
    if PLACEHOLDER.search(value):
        return "parece texto de exemplo"
    return None


def generic_value_skipped(value):
    return bool(PLACEHOLDER.search(value) or re.fullmatch(r"[a-z_.]+", value) or value.isdigit()
                or value.startswith(("$", "ENC[")))


def is_config(name, ext):
    return ext in CONFIG_EXT or name == ".env" or name.startswith(".env.")


def scan_secrets(text, arquivo, generic, hits, generic_count, config=False):
    # split("\n"), não splitlines(): este quebra também em \x0c, \x85 e U+2028, e a linha informada
    # deixaria de bater com a que o Read mostra.
    for number, line in enumerate(text.split("\n"), 1):
        if len(line) > 4000:
            line = line[:4000]
        found_specific = False
        for tipo, pattern, prefix_len in SECRET_PATTERNS:
            for m in pattern.finditer(line):
                value = m.group(1)
                if tipo == "chave privada":
                    shown = value
                elif tipo == "URL com usuário e senha":
                    scheme = value.split("://", 1)[0]
                    shown = "%s://<usuário>:<senha com %d caracteres>@<host>" % (
                        scheme, len(value.split("://", 1)[1].split("@", 1)[0].split(":", 1)[1]))
                    if PLACEHOLDER.search(value):
                        shown += " (parece exemplo)"
                else:
                    shown = mask(value, prefix_len)
                hits.append({"arquivo": arquivo, "linha": number, "tipo": tipo, "mascara": shown,
                             "exemplo": classify_example(value), "deteccao": "formato do provedor"})
                found_specific = True
        if generic and not found_specific and generic_count[0] < MAX_GENERIC_HITS:
            matches = list(GENERIC_SECRET.finditer(line))
            if config and not matches:
                matches = list(GENERIC_SECRET_UNQUOTED.finditer(line))
            for m in matches:
                value = m.group(2)
                if generic_value_skipped(value):
                    continue
                hits.append({"arquivo": arquivo, "linha": number, "tipo": "valor atribuído a '%s'" % m.group(1).lower(),
                             "mascara": mask(value, None), "exemplo": None, "deteccao": "atribuição genérica"})
                generic_count[0] += 1


# ---------------------------------------------------------------- varredura

def read_text(path):
    """Só arquivo comum: link simbólico apontaria para fora do repositório (~/.aws/credentials)
    e dispositivo como /dev/zero não terminaria de ser lido."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read(MAX_TEXT_BYTES + 1)
        if len(data) > MAX_TEXT_BYTES:
            return None
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def eligible(name, ext):
    """Código, configuração, manifesto e infraestrutura. Fora: lockfile gerado, binário, mídia,
    fonte tipográfica e documentação (salvo manifesto em .txt, como requirements.txt)."""
    if name in LOCK_NAMES or ext in BINARY_EXT:
        return False
    if ext in DOC_EXT and name not in MANIFEST_NAMES and not re.match(r"^requirements.*\.txt$", name):
        return False
    return True


def inventory(root, extra_excluded=(), diff_base=None, subdir=None):
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ValueError("raiz não encontrada: %s" % root)
    if diff_base and not BASE_REF.match(diff_base):
        raise ValueError("base de diff inválida: use só letras, números, '.', '_', '-' e '/'")
    start = os.path.abspath(os.path.join(root, subdir)) if subdir else root
    if not _inside(start, root) or not os.path.isdir(start):
        raise ValueError("subdiretório fora da raiz ou inexistente: %s" % subdir)

    excluded = EXCLUDED_DIRS | set(extra_excluded)
    excluded_found = set()
    elegiveis = []
    por_linguagem = {}
    manifestos, lockfiles, dockerfiles, compose, k8s, iac, ci = [], [], [], [], [], [], []
    agente, unicode_oculto, segredos, links = [], [], [], []
    generic_count = [0]
    c_cpp = 0

    for dirpath, dirnames, filenames in os.walk(start):
        keep = []
        for d in sorted(dirnames):
            if d in excluded:
                excluded_found.add(rel(root, os.path.join(dirpath, d)))
            elif os.path.islink(os.path.join(dirpath, d)):
                links.append(rel(root, os.path.join(dirpath, d)))  # os.walk não entra, mas fica registrado
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            arquivo = rel(root, path)
            if os.path.islink(path):
                links.append(arquivo)
                continue
            ext = os.path.splitext(name)[1].lower()
            if name in MANIFEST_NAMES or re.match(r"^requirements.*\.txt$", name):
                manifestos.append(arquivo)
            if name in LOCK_NAMES:
                lockfiles.append(arquivo)
            if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile"):
                dockerfiles.append(arquivo)
            if re.match(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$", name):
                compose.append(arquivo)
            if ext in (".tf", ".tfvars", ".hcl") or re.search(r"(cloudformation|\.template)\.(json|ya?ml)$", name):
                iac.append(arquivo)
            if any(p.search(arquivo) for p in CI_PATTERNS):
                ci.append(arquivo)
            if any(p.search(arquivo) for p in AGENT_CONFIG):
                agente.append(arquivo)
            if ext in C_CPP_EXT:
                c_cpp += 1
            if eligible(name, ext):
                elegiveis.append(arquivo)
                lang = LANGUAGES.get(ext, "Dockerfile" if arquivo in dockerfiles else "outro")
                por_linguagem[lang] = por_linguagem.get(lang, 0) + 1
            if ext in BINARY_EXT and name != "bun.lockb":
                continue
            text = read_text(path)
            if text is None:
                continue
            if ext in (".yml", ".yaml") and re.search(r"^\s*(apiVersion|kind):", text, re.MULTILINE) \
                    and re.search(r"^\s*kind:\s*\w+", text, re.MULTILINE):
                k8s.append(arquivo)
            scan_secrets(text, arquivo, generic=ext not in DOC_EXT, hits=segredos, generic_count=generic_count,
                         config=is_config(name, ext))
            if arquivo in agente:
                linhas = [n for n, l in enumerate(text.split("\n"), 1) if HIDDEN_UNICODE.search(l)]
                if linhas:
                    unicode_oculto.append({"arquivo": arquivo, "linhas": linhas[:50], "total": len(linhas)})

    info_git = git_info(root, diff_base)
    versionados = set(info_git["versionados"] or []) if info_git["versionados"] is not None else None
    for hit in segredos:
        hit["versionado"] = None if versionados is None else hit["arquivo"] in versionados

    escopo = {"tipo": "completo", "base": None, "subdiretorio": None, "arquivos": None}
    if subdir:
        escopo.update(tipo="subdiretorio", subdiretorio=rel(root, start))
    if info_git.get("diff"):
        alterados = info_git["diff"].get("alterados")
        conjunto = set(elegiveis)
        escopo.update(tipo="diff", base=diff_base,
                      arquivos=[a for a in (alterados or []) if a in conjunto])
    security_audit_versionado = None
    if versionados is not None:
        security_audit_versionado = sorted(v for v in versionados if v.startswith("security-audit/"))

    limites = [
        "Segredos procurados por formato de provedor em todo arquivo de texto e por atribuição "
        "genérica fora de documentação (até %d ocorrências genéricas); o histórico do git não é "
        "varrido." % MAX_GENERIC_HITS,
        "Arquivo acima de %d MB ou binário não é lido." % (MAX_TEXT_BYTES // (1024 * 1024)),
    ]
    if generic_count[0] >= MAX_GENERIC_HITS:
        limites.append("O teto de ocorrências genéricas foi atingido: há mais candidatos não listados.")
    if links:
        limites.append("%d link(s) simbólico(s) em `links_simbolicos` não foram seguidos, lidos nem "
                       "contados: o destino pode estar fora do repositório." % len(links))
    if info_git.get("erro"):
        limites.append(info_git["erro"])

    return {
        "ferramenta": "inventario",
        "versao": 1,
        "gerado_em": now_iso(),
        "raiz": root,
        "escopo": escopo,
        "git": {
            "repositorio": info_git["repositorio"],
            "versionados_total": None if versionados is None else len(versionados),
            "security_audit_versionado": security_audit_versionado,
            "erro": info_git.get("erro") or (info_git.get("diff") or {}).get("erro"),
        },
        "diretorios_excluidos": sorted(excluded_found),
        "arquivos_elegiveis": len(elegiveis),
        "por_linguagem": dict(sorted(por_linguagem.items(), key=lambda kv: -kv[1])),
        "manifestos": manifestos,
        "lockfiles": lockfiles,
        "infra": {"dockerfiles": dockerfiles, "compose": compose, "kubernetes": k8s,
                  "iac": iac, "ci": ci},
        "configuracao_de_agente": agente,
        "unicode_oculto": unicode_oculto,
        "c_cpp": {"arquivos": c_cpp, "fora_de_escopo": c_cpp > 0},
        "segredos_candidatos": segredos,
        "links_simbolicos": links,
        "elegiveis": elegiveis,
        "versionados": sorted(versionados) if versionados is not None else None,
        "limites": limites,
    }


def build_parser():
    parser = argparse.ArgumentParser(description="Inventário determinístico do projeto.")
    parser.add_argument("--raiz", required=True, help="raiz do projeto auditado")
    parser.add_argument("--saida", required=True, help="arquivo JSON de saída")
    parser.add_argument("--subdiretorio", help="restringe a varredura a este subdiretório da raiz")
    parser.add_argument("--diff", help="branch ou commit base: lista os arquivos alterados em <base>...HEAD")
    parser.add_argument("--excluir", action="append", default=[], help="diretório a excluir (repetível)")
    return parser


def configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv=None):
    configure_stdio()
    args = build_parser().parse_args(argv)
    try:
        resultado = inventory(args.raiz, args.excluir, args.diff, args.subdiretorio)
    except ValueError as exc:
        print("ERRO: %s" % exc, file=sys.stderr)
        return 2
    try:
        saida = os.path.abspath(args.saida)
        os.makedirs(os.path.dirname(saida), exist_ok=True)
        with open(saida, "w", encoding="utf-8") as fh:
            json.dump(resultado, fh, ensure_ascii=False, indent=1)
    except OSError as exc:
        print("ERRO: não foi possível gravar %s: %s" % (args.saida, exc), file=sys.stderr)
        return 3
    print("inventario: %d arquivo(s) elegível(is); %d segredo(s) candidato(s); git: %s; "
          "configuração de agente no repositório: %d; resultado em %s" % (
              resultado["arquivos_elegiveis"], len(resultado["segredos_candidatos"]),
              "sim" if resultado["git"]["repositorio"] else "não",
              len(resultado["configuracao_de_agente"]), saida))
    return 0


if __name__ == "__main__":
    sys.exit(main())
