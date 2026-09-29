"""Testes do sca_scan.py. Só biblioteca padrão; a rede do OSV é simulada.

Rode com:  python tests/test_sca_scan.py
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "skills", "cve", "scripts"))

import nvd_common  # noqa: E402
import sca_scan  # noqa: E402

LOCK_DO_EVAL = os.path.join(RAIZ, "evals", "auditoria-app-vulneravel", "projeto", "package-lock.json")


def escrever(base, relativo, conteudo):
    caminho = os.path.join(base, relativo)
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as fh:
        fh.write(conteudo)
    return caminho


class ProjetoTemporario(unittest.TestCase):
    def setUp(self):
        self.raiz = tempfile.mkdtemp(prefix="nist-sca-")
        self.extras = {"sem_pin": [], "fonte_fora_do_registro": []}

    def tearDown(self):
        shutil.rmtree(self.raiz, ignore_errors=True)

    def por_nome(self, pacotes):
        return {p["nome"]: p for p in pacotes}


class TestNpm(ProjetoTemporario):
    def test_lock_v3_diretos_transitivos_e_cadeia(self):
        caminho = os.path.join(self.raiz, "package-lock.json")
        shutil.copy(LOCK_DO_EVAL, caminho)
        pacotes = self.por_nome(sca_scan.parse_package_lock(self.raiz, caminho))
        self.assertEqual(set(pacotes), {"body-parser", "express", "jsonwebtoken", "lodash", "mysql", "qs"})
        self.assertTrue(pacotes["express"]["direto"])
        self.assertFalse(pacotes["qs"]["direto"])
        self.assertEqual(pacotes["qs"]["cadeia"], ["express", "qs"])
        self.assertEqual(pacotes["body-parser"]["cadeia"], ["express", "body-parser"])
        self.assertEqual(pacotes["lodash"]["versao"], "4.17.15")
        self.assertIsNotNone(pacotes["lodash"]["linha"])

    def test_lock_aninhado_resolve_versao_local(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "^1.0.0"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
                "node_modules/a/node_modules/b": {"version": "2.1.0"},
                "node_modules/b": {"version": "1.0.0", "dev": True},
            },
        }
        caminho = escrever(self.raiz, "package-lock.json", json.dumps(lock))
        pacotes = sca_scan.parse_package_lock(self.raiz, caminho)
        aninhado = [p for p in pacotes if p["nome"] == "b" and p["versao"] == "2.1.0"][0]
        self.assertEqual(aninhado["cadeia"], ["a", "b"])
        solto = [p for p in pacotes if p["nome"] == "b" and p["versao"] == "1.0.0"][0]
        self.assertTrue(solto["dev"])

    def test_yarn_v1_e_berry(self):
        v1 = ('# yarn lockfile v1\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n'
              '  version "7.12.13"\n  resolved "https://registry.yarnpkg.com/x"\n\n'
              'lodash@^4.17.15:\n  version "4.17.21"\n')
        caminho = escrever(self.raiz, "a/yarn.lock", v1)
        nomes = {(p["nome"], p["versao"]) for p in sca_scan.parse_yarn_lock(self.raiz, caminho)}
        self.assertEqual(nomes, {("@babel/code-frame", "7.12.13"), ("lodash", "4.17.21")})
        berry = ('__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n'
                 '  resolution: "lodash@npm:4.17.21"\n\n"@scope/x@npm:1.0.0":\n  resolution: "@scope/x@npm:1.0.0"\n')
        caminho = escrever(self.raiz, "b/yarn.lock", berry)
        nomes = {(p["nome"], p["versao"]) for p in sca_scan.parse_yarn_lock(self.raiz, caminho)}
        self.assertEqual(nomes, {("lodash", "4.17.21"), ("@scope/x", "1.0.0")})

    def test_pnpm(self):
        texto = ("lockfileVersion: '9.0'\n\npackages:\n\n  '@babel/core@7.20.0':\n    resolution: {}\n\n"
                 "  lodash@4.17.21:\n    resolution: {}\n\nsnapshots:\n\n  /qs@6.7.0(x@1.0.0):\n    dependencies: {}\n")
        caminho = escrever(self.raiz, "pnpm-lock.yaml", texto)
        nomes = {(p["nome"], p["versao"]) for p in sca_scan.parse_pnpm_lock(self.raiz, caminho)}
        self.assertEqual(nomes, {("@babel/core", "7.20.0"), ("lodash", "4.17.21"), ("qs", "6.7.0")})

    def test_package_json_faixas_e_fontes(self):
        manifesto = {"dependencies": {"a": "*", "b": "latest", "c": "^1.2.3",
                                      "d": "github:org/repo", "e": "git+https://x/y.git#" + "a" * 40,
                                      "f": ">=2.0.0"}}
        caminho = escrever(self.raiz, "package.json", json.dumps(manifesto, indent=2))
        sca_scan.check_package_json(self.raiz, caminho, True, self.extras)
        sem_pin = {i["nome"] for i in self.extras["sem_pin"]}
        self.assertEqual(sem_pin, {"a", "b", "f"})
        self.assertEqual({i["nome"] for i in self.extras["fonte_fora_do_registro"]}, {"d"})
        self.extras = {"sem_pin": [], "fonte_fora_do_registro": []}
        sca_scan.check_package_json(self.raiz, caminho, False, self.extras)
        self.assertIn("c", {i["nome"] for i in self.extras["sem_pin"]})

    def test_npmrc_nunca_devolve_token(self):
        caminho = escrever(self.raiz, ".npmrc",
                           "registry=https://npm.empresa.interna/\n"
                           "//npm.empresa.interna/:_authToken=tok_SEGREDO_123\n")
        sca_scan.check_npmrc(self.raiz, caminho, self.extras)
        texto = json.dumps(self.extras)
        self.assertNotIn("tok_SEGREDO_123", texto)
        self.assertIn("npm.empresa.interna", texto)


class TestPython(ProjetoTemporario):
    def test_requirements(self):
        texto = ("Flask==2.0.1 \\\n    --hash=sha256:abc\nrequests>=2.0\n"
                 "-e git+https://github.com/org/pkg.git#egg=pkg\n--extra-index-url https://pypi.empresa.io/simple\n"
                 "Django[argon2]==4.2.1 ; python_version >= '3.8'\n# comentário\n")
        caminho = escrever(self.raiz, "requirements.txt", texto)
        pacotes = self.por_nome(sca_scan.parse_requirements(self.raiz, caminho, self.extras))
        self.assertEqual(pacotes["flask"]["versao"], "2.0.1")
        self.assertEqual(pacotes["django"]["versao"], "4.2.1")
        self.assertEqual({i["nome"] for i in self.extras["sem_pin"]}, {"requests"})
        origens = " ".join(i["origem"] for i in self.extras["fonte_fora_do_registro"])
        self.assertIn("github.com", origens)
        self.assertIn("pypi.empresa.io", origens)

    def test_poetry_e_uv(self):
        poetry = ('[[package]]\nname = "Requests"\nversion = "2.31.0"\n\n'
                  '[[package]]\nname = "interno"\nversion = "0.1.0"\n\n[package.source]\ntype = "git"\n'
                  'url = "https://git.empresa/interno.git"\n')
        caminho = escrever(self.raiz, "poetry.lock", poetry)
        pacotes = self.por_nome(sca_scan.parse_poetry_or_uv(self.raiz, caminho, self.extras))
        self.assertEqual(pacotes["requests"]["versao"], "2.31.0")
        self.assertIn("interno", {i["nome"] for i in self.extras["fonte_fora_do_registro"]})
        uv = ('version = 1\n\n[[package]]\nname = "meu-app"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
              '[[package]]\nname = "urllib3"\nversion = "1.26.5"\nsource = { registry = "https://pypi.org/simple" }\n')
        caminho = escrever(self.raiz, "sub/uv.lock", uv)
        nomes = {p["nome"] for p in sca_scan.parse_poetry_or_uv(self.raiz, caminho, self.extras)}
        self.assertEqual(nomes, {"urllib3"})


class TestOutrosEcossistemas(ProjetoTemporario):
    def test_go_mod(self):
        texto = ("module x\n\ngo 1.21.4\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n"
                 "\tgolang.org/x/net v0.10.0 // indirect\n)\n\nrequire github.com/a/b v0.1.0\n\n"
                 "replace github.com/a/b => ../b\n")
        caminho = escrever(self.raiz, "go.mod", texto)
        pacotes = self.por_nome(sca_scan.parse_go_mod(self.raiz, caminho, self.extras))
        self.assertEqual(pacotes["github.com/gin-gonic/gin"]["versao"], "1.9.0")
        self.assertFalse(pacotes["golang.org/x/net"]["direto"])
        self.assertEqual(pacotes["stdlib"]["versao"], "1.21.4")
        self.assertTrue(self.extras["fonte_fora_do_registro"])

    def test_cargo_lock(self):
        texto = ('[[package]]\nname = "meu"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\n'
                 'version = "1.0.100"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                 '[[package]]\nname = "fork"\nversion = "0.2.0"\nsource = "git+https://github.com/o/fork#abc"\n')
        caminho = escrever(self.raiz, "Cargo.lock", texto)
        pacotes = self.por_nome(sca_scan.parse_cargo_lock(self.raiz, caminho, self.extras))
        self.assertEqual(set(pacotes), {"serde", "fork"})
        self.assertEqual({i["nome"] for i in self.extras["fonte_fora_do_registro"]}, {"fork"})

    def test_composer_gemfile_nuget_gradle(self):
        composer = {"packages": [{"name": "symfony/http-kernel", "version": "v5.4.0", "license": ["MIT"]}],
                    "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}
        caminho = escrever(self.raiz, "composer.lock", json.dumps(composer, indent=2))
        pacotes = self.por_nome(sca_scan.parse_composer_lock(self.raiz, caminho, self.extras))
        self.assertEqual(pacotes["symfony/http-kernel"]["versao"], "5.4.0")
        self.assertEqual(pacotes["symfony/http-kernel"]["licenca"], "MIT")
        self.assertTrue(pacotes["phpunit/phpunit"]["dev"])

        gemfile = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.1-x86_64-linux)\n"
                   "      racc (~> 1.4)\n    racc (1.6.0)\n\nPLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  nokogiri\n")
        caminho = escrever(self.raiz, "Gemfile.lock", gemfile)
        pacotes = self.por_nome(sca_scan.parse_gemfile_lock(self.raiz, caminho, self.extras))
        self.assertEqual(pacotes["nokogiri"]["versao"], "1.13.1")
        self.assertTrue(pacotes["nokogiri"]["direto"])
        self.assertFalse(pacotes["racc"]["direto"])

        nuget = {"version": 1, "dependencies": {"net6.0": {
            "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"},
            "Meu.Projeto": {"type": "Project"}}}}
        caminho = escrever(self.raiz, "packages.lock.json", json.dumps(nuget))
        pacotes = self.por_nome(sca_scan.parse_nuget_lock(self.raiz, caminho, self.extras))
        self.assertEqual(set(pacotes), {"Newtonsoft.Json"})

        gradle = "# comentário\ncom.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n"
        caminho = escrever(self.raiz, "gradle.lockfile", gradle)
        pacotes = self.por_nome(sca_scan.parse_gradle_lockfile(self.raiz, caminho, self.extras))
        self.assertEqual(pacotes["com.google.guava:guava"]["versao"], "31.1-jre")


class TestCvss(unittest.TestCase):
    def test_notas_conhecidas(self):
        casos = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vetor, nota in casos.items():
            self.assertEqual(sca_scan.cvss3_score(vetor), nota, vetor)
        self.assertIsNone(sca_scan.cvss3_score("CVSS:4.0/AV:N/AC:L"))
        self.assertEqual(sca_scan.severity_name(9.8), "CRITICAL")


class _OsvFalso:
    def __init__(self, ids_por_pacote, detalhes, falhar=False):
        self.ids = ids_por_pacote
        self.detalhes = detalhes
        self.falhar = falhar
        self.enviados = []

    def __call__(self, url, body=None, **kw):
        if self.falhar:
            raise sca_scan.ScanError("falha de rede ao consultar o OSV: URLError")
        if body is not None:
            self.enviados.extend(q["package"]["name"] for q in body["queries"])
            return {"results": [{"vulns": [{"id": i} for i in self.ids.get(q["package"]["name"], [])]}
                                for q in body["queries"]]}
        vid = url.rsplit("/", 1)[-1]
        return self.detalhes.get(vid)


GHSA_QS = {
    "id": "GHSA-hrpp-h998-j3pp",
    "aliases": ["CVE-2022-24999"],
    "summary": "qs vulnerable to Prototype Pollution",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
    "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.7.0"}, {"fixed": "6.7.3"}]}]}],
}
MAL_LODASH = {"id": "MAL-2025-0001", "summary": "Malicious code in lodash", "affected": [
    {"package": {"ecosystem": "npm", "name": "lodash"}}]}
RETIRADO = {"id": "GHSA-xxxx-yyyy-zzzz", "withdrawn": "2024-01-01T00:00:00Z", "affected": []}


class TestScan(unittest.TestCase):
    def setUp(self):
        self.raiz = tempfile.mkdtemp(prefix="nist-scan-")
        shutil.copytree(os.path.join(RAIZ, "evals", "auditoria-app-vulneravel", "projeto"),
                        self.raiz, dirs_exist_ok=True)
        self.orig = sca_scan.http_json

    def tearDown(self):
        sca_scan.http_json = self.orig
        shutil.rmtree(self.raiz, ignore_errors=True)

    def test_consulta_osv_com_fixo_malicioso_e_retirado(self):
        falso = _OsvFalso({"qs": ["GHSA-hrpp-h998-j3pp", "GHSA-xxxx-yyyy-zzzz"], "lodash": ["MAL-2025-0001"]},
                          {"GHSA-hrpp-h998-j3pp": GHSA_QS, "MAL-2025-0001": MAL_LODASH, "GHSA-xxxx-yyyy-zzzz": RETIRADO})
        sca_scan.http_json = falso
        resultado = sca_scan.scan(self.raiz)
        vulneraveis = {p["nome"]: p for p in resultado["vulneraveis"]}
        qs = vulneraveis["qs"]["vulnerabilidades"]
        self.assertEqual(len(qs), 1)
        self.assertEqual(qs[0]["cve"], ["CVE-2022-24999"])
        self.assertEqual(qs[0]["corrigido_em"], ["6.7.3"])
        self.assertEqual(qs[0]["severidade"]["nota"], 7.5)
        self.assertEqual(vulneraveis["qs"]["cadeia"], ["express", "qs"])
        self.assertEqual([p["nome"] for p in resultado["maliciosos"]], ["lodash"])
        self.assertEqual(resultado["consulta"]["status"], "ok")

    def test_pacote_de_registro_privado_nao_e_enviado(self):
        caminho = os.path.join(self.raiz, "package-lock.json")
        with open(caminho, encoding="utf-8") as fh:
            lock = json.load(fh)
        lock["packages"]["node_modules/mysql"]["resolved"] = "https://npm.empresa.interna/mysql-2.18.1.tgz"
        with open(caminho, "w", encoding="utf-8") as fh:
            json.dump(lock, fh)
        falso = _OsvFalso({}, {})
        sca_scan.http_json = falso
        resultado = sca_scan.scan(self.raiz)
        self.assertNotIn("mysql", falso.enviados)
        self.assertIn("mysql", {n["nome"] for n in resultado["consulta"]["nao_enviados"]})

    def test_falha_do_osv_fica_registrada_e_o_inventario_sai(self):
        sca_scan.http_json = _OsvFalso({}, {}, falhar=True)
        resultado = sca_scan.scan(self.raiz)
        self.assertEqual(resultado["consulta"]["status"], "falhou")
        self.assertEqual(resultado["inventario"]["total"], 6)

    def test_enriquece_pela_base_local(self):
        db = os.path.join(self.raiz, "nvd.sqlite")
        conn = nvd_common.connect(db)
        nvd_common.init_schema(conn)
        nvd_common.upsert_cve(conn, {
            "id": "CVE-2022-24999", "vulnStatus": "Analyzed", "cisaExploitAdd": "2023-01-10",
            "descriptions": [{"lang": "en", "value": "qs prototype pollution"}],
            "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
                "baseScore": 7.5, "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-1321"}]}],
        })
        conn.commit()
        conn.close()
        sca_scan.http_json = _OsvFalso({"qs": ["GHSA-hrpp-h998-j3pp"]}, {"GHSA-hrpp-h998-j3pp": GHSA_QS})
        resultado = sca_scan.scan(self.raiz, db=db)
        vuln = [p for p in resultado["vulneraveis"] if p["nome"] == "qs"][0]["vulnerabilidades"][0]
        self.assertTrue(vuln["severidade"]["fonte"].startswith("NVD local"))
        self.assertEqual(vuln["kev"], "2023-01-10")

    def test_main_offline_grava_json_e_nao_usa_rede(self):
        sca_scan.http_json = _OsvFalso({}, {}, falhar=True)
        saida = os.path.join(self.raiz, "security-audit", ".trabalho", "sca.json")
        texto = io.StringIO()
        with contextlib.redirect_stdout(texto):
            codigo = sca_scan.main(["--raiz", self.raiz, "--saida", saida, "--offline"])
        self.assertEqual(codigo, 0)
        with open(saida, encoding="utf-8") as fh:
            resultado = json.load(fh)
        self.assertIn("desligada", resultado["consulta"]["fonte"])
        self.assertEqual(resultado["inventario"]["por_ecossistema"], {"npm": 6})
        self.assertEqual(resultado["sem_lockfile"], [])


# Tokens falsos montados por concatenação, como no test_inventario.py.
TOKEN_FALSO = "ghp_" + "Zx9Kq2" * 6
SENHA_FALSA = "Pw7" + "rTq4Ln8Vx"


class _OsvGravador(_OsvFalso):
    """Guarda o corpo inteiro de cada consulta, para conferir o que sairia da máquina."""

    def __init__(self):
        super().__init__({}, {})
        self.corpos = []

    def __call__(self, url, body=None, **kw):
        if body is not None:
            self.corpos.append(json.loads(json.dumps(body)))
        return super().__call__(url, body, **kw)


class TestPrivacidade(ProjetoTemporario):
    def setUp(self):
        super().setUp()
        self.orig = sca_scan.http_json
        self.gravador = _OsvGravador()
        sca_scan.http_json = self.gravador

    def tearDown(self):
        sca_scan.http_json = self.orig
        super().tearDown()

    def montar_projeto(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"express": "4.18.2"}},
            "node_modules/express": {"version": "4.18.2",
                                     "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"},
            "packages/app-interno": {"name": "@empresa/app-interno", "version": "1.0.0"},
            "packages/app-interno/node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@empresa/sdk": {"version": "2.0.0",
                                          "resolved": "https://registry.npmjs.org/@empresa/sdk/-/sdk-2.0.0.tgz"},
            "node_modules/via-git": {"version": "git+https://%s@github.com/empresa/via-git.git#abc" % TOKEN_FALSO},
        }}
        escrever(self.raiz, "package-lock.json", json.dumps(lock))
        escrever(self.raiz, ".npmrc", "@empresa:registry=https://npm.empresa.interna/\n")
        escrever(self.raiz, "web/yarn.lock", '# yarn lockfile v1\n\nleft-pad@^1.0.0:\n  version "1.3.0"\n'
                 '  resolved "https://npm.empresa.interna/left-pad-1.3.0.tgz"\n\nqs@^6.0.0:\n  version "6.11.0"\n'
                 '  resolved "https://registry.yarnpkg.com/qs/-/qs-6.11.0.tgz"\n')
        escrever(self.raiz, "front/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n"
                 "  ui-privado@3.1.0:\n    resolution: {integrity: sha512-x, tarball: https://npm.empresa.interna/ui-privado-3.1.0.tgz}\n\n"
                 "  react@18.2.0:\n    resolution: {integrity: sha512-y}\n")
        escrever(self.raiz, "py/poetry.lock",
                 '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
                 '[[package]]\nname = "cobranca-interna"\nversion = "0.3.0"\n\n[package.source]\ntype = "legacy"\n'
                 'url = "https://pypi.empresa.interna/simple"\nreference = "empresa"\n\n'
                 '[[package]]\nname = "lib-local"\nversion = "0.1.0"\n\n[package.source]\ntype = "directory"\nurl = "../lib"\n')
        escrever(self.raiz, "svc/go.mod", "module github.com/empresa/svc\n\ngo 1.22\n\nrequire (\n"
                 "\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/empresa/segredo-interno v0.4.0\n)\n")
        escrever(self.raiz, "rs/Cargo.lock", '[[package]]\nname = "fork-interno"\nversion = "0.2.0"\n'
                 'source = "git+https://%s@git.empresa.interna/fork.git#abc"\n' % TOKEN_FALSO)

    def test_consulta_leva_so_nome_ecossistema_e_versao_e_nada_privado(self):
        self.montar_projeto()
        with mock.patch.dict(os.environ, {"GOPRIVATE": "github.com/empresa/*"}):
            resultado = sca_scan.scan(self.raiz)
        consultas = [q for corpo in self.gravador.corpos for q in corpo["queries"]]
        self.assertTrue(consultas)
        for q in consultas:
            self.assertEqual(set(q), {"package", "version"})
            self.assertEqual(set(q["package"]), {"name", "ecosystem"})
        enviados = {q["package"]["name"] for q in consultas}
        self.assertTrue({"express", "qs", "react", "requests", "github.com/gin-gonic/gin"} <= enviados, enviados)
        privados = {"@empresa/app-interno", "@empresa/sdk", "via-git", "left-pad", "ui-privado",
                    "cobranca-interna", "lib-local", "github.com/empresa/segredo-interno", "fork-interno"}
        self.assertFalse(privados & enviados, privados & enviados)
        corpo_bruto = json.dumps(self.gravador.corpos)
        self.assertNotIn(TOKEN_FALSO, corpo_bruto)
        self.assertNotIn("empresa.interna", corpo_bruto)
        motivos = {n["nome"]: n["motivo"] for n in resultado["consulta"]["nao_enviados"]}
        self.assertIn("escopo npm", motivos["@empresa/sdk"])
        self.assertIn("GOPRIVATE", motivos["github.com/empresa/segredo-interno"])

    def test_credencial_de_url_nao_vai_para_o_json(self):
        self.montar_projeto()
        escrever(self.raiz, "rb/Gemfile.lock", "GIT\n  remote: https://deploy:%s@git.empresa.interna/gem.git\n"
                 "  revision: abc\n  specs:\n    gem-interna (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n"
                 "  specs:\n    rack (2.2.8)\n\nDEPENDENCIES\n  rack\n" % SENHA_FALSA)
        with open(os.path.join(self.raiz, "package-lock.json"), encoding="utf-8") as fh:
            lock = json.load(fh)
        lock["packages"]["node_modules/express"]["resolved"] = "https://u:%s@registry.npmjs.org/express.tgz" % SENHA_FALSA
        escrever(self.raiz, "package-lock.json", json.dumps(lock))
        texto = json.dumps(sca_scan.scan(self.raiz, offline=True), ensure_ascii=False)
        self.assertNotIn(TOKEN_FALSO, texto)
        self.assertNotIn(SENHA_FALSA, texto)
        self.assertIn("<credencial removida>@", texto)

    def test_sem_credencial(self):
        self.assertEqual(sca_scan.sem_credencial("https://%s@github.com/o/r" % TOKEN_FALSO),
                         "https://<credencial removida>@github.com/o/r")
        self.assertEqual(sca_scan.sem_credencial("git+ssh://git@github.com/o/r.git"), "git+ssh://git@github.com/o/r.git")
        self.assertEqual(sca_scan.sem_credencial("https://registry.npmjs.org/x.tgz"), "https://registry.npmjs.org/x.tgz")
        self.assertIsNone(sca_scan.sem_credencial(None))


class TestRobustez(ProjetoTemporario):
    def test_lockfile_malformado_vira_erro_e_o_scan_continua(self):
        escrever(self.raiz, "bom/package-lock.json", json.dumps(
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/qs": {"version": "6.11.0"}}}))
        escrever(self.raiz, "a/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": "1.0"}}))
        escrever(self.raiz, "b/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": [1]}))
        escrever(self.raiz, "c/Pipfile.lock", json.dumps({"default": {"flask": "2.0.1"}}))
        escrever(self.raiz, "d/composer.lock", json.dumps({"packages": ["x"]}))
        escrever(self.raiz, "e/packages.lock.json", json.dumps({"dependencies": {"net6.0": {"X": "1.0"}}}))
        escrever(self.raiz, "f/Cargo.lock", '[[package]]\nname = "x"\nversion = "1.0.0"\nsource = 1\n')
        escrever(self.raiz, "g/poetry.lock", 'package = ["x"]\n')
        escrever(self.raiz, "h/package-lock.json", "[" * 100000 + "]" * 100000)
        escrever(self.raiz, "i/package-lock.json", json.dumps(
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/y": {"version": ["1.0.0"]}}}))
        resultado = sca_scan.scan(self.raiz, offline=True)
        self.assertEqual(resultado["inventario"]["total"], 1)  # só o qs do lockfile bom
        falhos = {e.split(":", 1)[0] for e in resultado["erros"]}
        esperados = {"a/package-lock.json", "b/package-lock.json", "c/Pipfile.lock", "d/composer.lock",
                     "e/packages.lock.json", "f/Cargo.lock", "g/poetry.lock", "h/package-lock.json",
                     "i/package-lock.json"}
        self.assertEqual(falhos, esperados)

    def test_link_simbolico_nao_e_lido(self):
        fora = tempfile.mkdtemp(prefix="nist-fora-")
        self.addCleanup(shutil.rmtree, fora, True)
        alvo = escrever(fora, "credentials", "aws_secret_access_key = " + SENHA_FALSA + "\n")
        try:
            os.symlink(alvo, os.path.join(self.raiz, "requirements.txt"))
        except (OSError, NotImplementedError):
            self.skipTest("este ambiente não permite criar link simbólico")
        resultado = sca_scan.scan(self.raiz, offline=True)
        self.assertNotIn(SENHA_FALSA, json.dumps(resultado))
        self.assertTrue(any("link simbólico" in e for e in resultado["erros"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
