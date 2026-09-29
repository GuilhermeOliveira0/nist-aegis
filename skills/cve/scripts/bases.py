"""Onde ficam as bases locais do plugin.

    ~/.nist-aegis/
    ├── bases/
    │   ├── nvd.sqlite     espelho da NVD (download_db.py)
    │   └── osv.sqlite     espelho do OSV (download_osv.py)
    └── downloads/         arquivos do OSV em trânsito, apagados depois da importação

NIST_AEGIS_HOME troca a pasta raiz. A NVD de versões anteriores, em ~/.nvd/nvd.sqlite, continua
sendo encontrada enquanto não houver uma em bases/.
"""

import os


def home():
    raiz = os.environ.get("NIST_AEGIS_HOME", "").strip() or os.path.join("~", ".nist-aegis")
    return os.path.abspath(os.path.expanduser(raiz))


def bases_dir():
    return os.path.join(home(), "bases")


def downloads_dir():
    return os.path.join(home(), "downloads")


def nvd_default():
    return os.path.join(bases_dir(), "nvd.sqlite")


def osv_default():
    return os.path.join(bases_dir(), "osv.sqlite")


def nvd_legacy():
    return os.path.abspath(os.path.expanduser(os.path.join("~", ".nvd", "nvd.sqlite")))


def resolve_nvd(caminho=None):
    """Caminho explícito vence. Sem ele, a base em bases/; se ela não existir e a antiga existir,
    a antiga."""
    if caminho:
        return os.path.abspath(os.path.expanduser(caminho))
    nova = nvd_default()
    if not os.path.exists(nova) and os.path.exists(nvd_legacy()):
        return nvd_legacy()
    return nova


def resolve_osv(caminho=None):
    if caminho:
        return os.path.abspath(os.path.expanduser(caminho))
    return osv_default()
