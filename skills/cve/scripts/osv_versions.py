"""Comparação de versões por ecossistema e avaliação das faixas do OSV, sem rede.

Cada ecossistema ordena versões do seu jeito, e errar aqui faz uma versão vulnerável parecer
segura. Por isso:

- cada comparador segue a regra publicada do ecossistema (SemVer 2.0, PEP 440, ComparableVersion
  do Maven, Gem::Version, NuGetVersion, version_compare do PHP usado pelo Composer);
- versão que o comparador não reconhece levanta `VersaoInvalida`, e quem chama marca o pacote
  como "não avaliado" em vez de "sem vulnerabilidade";
- a lista `versions` do registro, quando existe, é conferida antes das faixas.

A avaliação de faixa segue o algoritmo da especificação do OSV (seção "Evaluation"): eventos
ordenados por versão, `introduced` liga, `fixed` desliga a partir da versão, `last_affected`
desliga depois dela. Faixa do tipo GIT é ignorada: casa commit, não versão de pacote.

Só biblioteca padrão.
"""

import functools
import re


class VersaoInvalida(ValueError):
    pass


# ---------------------------------------------------------------- SemVer 2.0 (npm, Go, crates.io)

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*|\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver_pre(pre):
    if pre is None:
        return (1,)  # versão final vem depois de qualquer pré-lançamento
    ids = []
    for ident in pre.split("."):
        ids.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
    return (0, tuple(ids))


def semver_key(version):
    m = _SEMVER.match(version.strip())
    if not m:
        raise VersaoInvalida("não é SemVer: %r" % version)
    major, minor, patch, pre = m.groups()
    return (int(major), int(minor or 0), int(patch or 0), _semver_pre(pre))


# ---------------------------------------------------------------- PEP 440 (PyPI)

_PEP440 = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def pep440_key(version):
    """Mesma ordem de packaging.version.Version._cmpkey, codificada em tuplas comparáveis."""
    m = _PEP440.match(version)
    if not m:
        raise VersaoInvalida("não é PEP 440: %r" % version)
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = post = dev = None
    if m.group("pre_l"):
        pre = (_PRE_RANK[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    if m.group("post"):
        post = int(m.group("post_n1") or m.group("post_n2") or 0)
    if m.group("dev_l"):
        dev = int(m.group("dev_n") or 0)
    if pre is None and post is None and dev is not None:
        pre_k = (0,)            # 1.0.dev0 vem antes de 1.0a1
    elif pre is None:
        pre_k = (2,)            # sem pré-lançamento: depois de todos eles
    else:
        pre_k = (1,) + pre
    post_k = (0,) if post is None else (1, post)
    dev_k = (1,) if dev is None else (0, dev)
    if m.group("local"):
        partes = re.split(r"[-_.]", m.group("local").lower())
        local_k = (1, tuple((1, int(p), "") if p.isdigit() else (0, 0, p) for p in partes))
    else:
        local_k = (0,)
    return (int(m.group("epoch") or 0), tuple(release), pre_k, post_k, dev_k, local_k)


# ---------------------------------------------------------------- Maven (ComparableVersion)

_MAVEN_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_MAVEN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_MAVEN_RELEASE = str(_MAVEN_QUALIFIERS.index(""))


def _maven_qualifier(value):
    value = _MAVEN_ALIASES.get(value, value)
    if value in _MAVEN_QUALIFIERS:
        return str(_MAVEN_QUALIFIERS.index(value))
    return "%d-%s" % (len(_MAVEN_QUALIFIERS), value)


class _MInt:
    def __init__(self, v):
        self.v = v

    def null(self):
        return self.v == 0


class _MStr:
    def __init__(self, v, followed_by_digit=False):
        if followed_by_digit and len(v) == 1:
            v = {"a": "alpha", "b": "beta", "m": "milestone"}.get(v, v)
        self.v = _MAVEN_ALIASES.get(v, v)

    def null(self):
        return _maven_qualifier(self.v) == _MAVEN_RELEASE


class _MList(list):
    def null(self):
        return len(self) == 0

    def normalize(self):
        i = len(self) - 1
        while i >= 0:
            item = self[i]
            if item.null():
                del self[i]
            elif not isinstance(item, _MList):
                break
            i -= 1


def _maven_cmp(a, b):
    """Compara dois itens; b pode ser None (item ausente)."""
    if isinstance(a, _MInt):
        if b is None:
            return 0 if a.v == 0 else 1
        if isinstance(b, _MInt):
            return (a.v > b.v) - (a.v < b.v)
        return 1  # número vem depois de texto e de sublista
    if isinstance(a, _MStr):
        qa = _maven_qualifier(a.v)
        if b is None:
            return (qa > _MAVEN_RELEASE) - (qa < _MAVEN_RELEASE)
        if isinstance(b, _MInt):
            return -1
        if isinstance(b, _MStr):
            qb = _maven_qualifier(b.v)
            return (qa > qb) - (qa < qb)
        return -1
    # sublista
    if b is None:
        return 0 if not a else _maven_cmp(a[0], None)
    if isinstance(b, _MInt):
        return -1
    if isinstance(b, _MStr):
        return 1
    for i in range(max(len(a), len(b))):
        l = a[i] if i < len(a) else None
        r = b[i] if i < len(b) else None
        c = _maven_cmp(l, r) if l is not None else -_maven_cmp(r, None) if r is not None else 0
        if c:
            return c
    return 0


def _maven_parse(version):
    version = version.strip().lower()
    if not version or not re.fullmatch(r"[0-9a-z.\-_+]+", version):
        raise VersaoInvalida("não é versão Maven: %r" % version)
    root = _MList()
    current = root
    stack = [root]
    start = 0
    is_digit = False

    def item(text, digit, next_is_digit=False):
        return _MInt(int(text)) if digit else _MStr(text, next_is_digit)

    i = 0
    while i < len(version):
        c = version[i]
        if c == ".":
            current.append(_MInt(0) if i == start else item(version[start:i], is_digit))
            start = i + 1
        elif c == "-":
            current.append(_MInt(0) if i == start else item(version[start:i], is_digit))
            start = i + 1
            sub = _MList()
            current.append(sub)
            current = sub
            stack.append(sub)
        elif c.isdigit():
            if not is_digit and i > start:
                current.append(_MStr(version[start:i], True))
                start = i
                sub = _MList()
                current.append(sub)
                current = sub
                stack.append(sub)
            is_digit = True
        else:
            if is_digit and i > start:
                current.append(item(version[start:i], True))
                start = i
                sub = _MList()
                current.append(sub)
                current = sub
                stack.append(sub)
            is_digit = False
        i += 1
    if len(version) > start:
        current.append(item(version[start:], is_digit))
    for lista in reversed(stack):
        lista.normalize()
    return root


def maven_key(version):
    return functools.cmp_to_key(_maven_cmp)(_maven_parse(version))


# ---------------------------------------------------------------- RubyGems (Gem::Version)

_GEM = re.compile(r"^\s*[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\s*$")


def _gem_segments(version):
    if not _GEM.match(version):
        raise VersaoInvalida("não é versão RubyGems: %r" % version)
    texto = version.strip().replace("-", ".pre.")
    segs = [int(s) if s.isdigit() else s for s in re.findall(r"[0-9]+|[a-z]+", texto, re.IGNORECASE)]
    corte = next((i for i, s in enumerate(segs) if isinstance(s, str)), len(segs))
    numericos, textos = segs[:corte], segs[corte:]
    while numericos and numericos[-1] == 0:
        numericos.pop()
    while textos and textos[-1] == 0:
        textos.pop()
    return numericos + textos


def _gem_cmp(a, b):
    for i in range(max(len(a), len(b))):
        l = a[i] if i < len(a) else 0
        r = b[i] if i < len(b) else 0
        if l == r:
            continue
        if isinstance(l, str) and isinstance(r, int):
            return -1
        if isinstance(l, int) and isinstance(r, str):
            return 1
        return (l > r) - (l < r)
    return 0


def gem_key(version):
    return functools.cmp_to_key(_gem_cmp)(_gem_segments(version))


# ---------------------------------------------------------------- NuGet (NuGetVersion)

_NUGET = re.compile(r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
                    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?\s*$")


def nuget_key(version):
    m = _NUGET.match(version)
    if not m:
        raise VersaoInvalida("não é versão NuGet: %r" % version)
    partes = tuple(int(x or 0) for x in m.groups()[:4])
    pre = m.group(5)
    return partes + (_semver_pre(pre.lower() if pre else None),)


# ---------------------------------------------------------------- Composer / Packagist (version_compare)

# Ordem e valores de compare_special_version_forms do PHP; o casamento é por prefixo.
_PHP_SPECIAL = (("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("RC", 3), ("rc", 3),
                ("#", 4), ("pl", 5), ("p", 5))


def _php_canon(version):
    v = version.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    if not v or not re.fullmatch(r"[0-9A-Za-z.\-_+]+", v):
        raise VersaoInvalida("não é versão Composer: %r" % version)
    v = re.sub(r"[-_+]", ".", v)
    v = re.sub(r"(?<=\d)(?=[^\d.])|(?<=[^\d.])(?=\d)", ".", v)
    return [p for p in v.split(".") if p != ""]


def _php_special(p):
    for nome, valor in _PHP_SPECIAL:
        if p.startswith(nome):
            return valor
    return -6  # texto desconhecido vem antes de "dev"


def _php_part_cmp(a, b):
    ad, bd = a.isdigit(), b.isdigit()
    if ad and bd:
        return (int(a) > int(b)) - (int(a) < int(b))
    x = 4 if ad else _php_special(a)
    y = 4 if bd else _php_special(b)
    return (x > y) - (x < y)


def _php_cmp(a, b):
    for i in range(min(len(a), len(b))):
        c = _php_part_cmp(a[i], b[i])
        if c:
            return c
    if len(a) > len(b):
        return 1 if a[len(b)].isdigit() else _php_part_cmp(a[len(b)], "#")
    if len(b) > len(a):
        return -1 if b[len(a)].isdigit() else -_php_part_cmp(b[len(a)], "#")
    return 0


def composer_key(version):
    return functools.cmp_to_key(_php_cmp)(_php_canon(version))


# ---------------------------------------------------------------- escolha e avaliação

ECOSYSTEM_KEYS = {
    "npm": semver_key, "Go": semver_key, "crates.io": semver_key,
    "PyPI": pep440_key, "Maven": maven_key, "RubyGems": gem_key,
    "NuGet": nuget_key, "Packagist": composer_key,
}


def key_function(ecosystem, range_type):
    if range_type == "SEMVER":
        return semver_key
    if range_type == "ECOSYSTEM" and ecosystem in ECOSYSTEM_KEYS:
        return ECOSYSTEM_KEYS[ecosystem]
    raise VersaoInvalida("faixa %s sem comparador para %s" % (range_type, ecosystem))


def _in_range(version_key, events, key):
    """Algoritmo da especificação: ordena os eventos e aplica em sequência."""
    ordenados = []
    for evt in events:
        if "introduced" in evt:
            valor = evt["introduced"]
            ordenados.append(((0,) if valor == "0" else (1, key(valor)), "introduced", valor))
        elif "fixed" in evt:
            ordenados.append(((1, key(evt["fixed"])), "fixed", evt["fixed"]))
        elif "last_affected" in evt:
            ordenados.append(((1, key(evt["last_affected"])), "last_affected", evt["last_affected"]))
        # "limit" só vale para GIT
    ordenados.sort(key=lambda e: e[0])
    vulneravel = False
    for posicao, tipo, _ in ordenados:
        alvo = (1, version_key)
        if tipo == "introduced" and alvo >= posicao:
            vulneravel = True
        elif tipo == "fixed" and alvo >= posicao:
            vulneravel = False
        elif tipo == "last_affected" and alvo > posicao:
            vulneravel = False
    return vulneravel


def _in_versions(ecosystem, version, versoes):
    """Lista explícita, com normalização do ecossistema (no PyPI, 1.0 == 1.0.0)."""
    key = ECOSYSTEM_KEYS.get(ecosystem)
    if key is None:
        return None
    try:
        alvo = key(version)
    except VersaoInvalida:
        return None
    for v in versoes:
        try:
            if key(v) == alvo:
                return True
        except VersaoInvalida:
            continue
    return False


def is_affected(ecosystem, version, affected):
    """True (afetada), False (não afetada) ou None (não deu para avaliar: quem chama deve
    registrar "não avaliado", nunca "sem vulnerabilidade")."""
    versoes = affected.get("versions") or []
    if version in versoes:
        return True
    todas = affected.get("ranges") or []
    faixas = [r for r in todas if r.get("type") != "GIT"]
    if not faixas:
        if versoes:
            return _in_versions(ecosystem, version, versoes)
        if todas:
            return None  # só faixa de commit: não dá para dizer pela versão
        return True      # sem faixa nem lista (típico de pacote malicioso): toda versão
    indeterminado = False
    for rng in faixas:
        try:
            key = key_function(ecosystem, rng.get("type"))
            if _in_range(key(version), rng.get("events") or [], key):
                return True
        except VersaoInvalida:
            indeterminado = True
    if versoes and _in_versions(ecosystem, version, versoes):
        return True
    return None if indeterminado else False
