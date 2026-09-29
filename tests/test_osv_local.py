"""Testes da base OSV local, do download_osv.py e do sca_scan.py --osv-local.

Só biblioteca padrão; a rede é sempre simulada.
Rode com:  python tests/test_osv_local.py
"""

import base64
import email.message
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from unittest import mock

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "skills", "cve", "scripts"))
sys.path.insert(0, os.path.join(RAIZ, "tests"))

import bases  # noqa: E402
import download_osv  # noqa: E402
import osv_local  # noqa: E402
import sca_scan  # noqa: E402
from test_sca_scan import GHSA_QS, MAL_LODASH, RETIRADO  # noqa: E402


def registro(vid, eco, nome, eventos=None, versoes=None, **extra):
    aff = {"package": {"ecosystem": eco, "name": nome}}
    if eventos is not None:
        aff["ranges"] = [{"type": "SEMVER" if eco in ("npm", "Go", "crates.io") else "ECOSYSTEM",
                          "events": [dict([e]) for e in eventos]}]
    if versoes is not None:
        aff["versions"] = versoes
    reg = {"id": vid, "modified": "2026-01-01T00:00:00Z", "affected": [aff]}
    reg.update(extra)
    return reg


def zip_de(registros):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for r in registros:
            zf.writestr("%s.json" % r["id"], json.dumps(r))
    return buf.getvalue()


class _Resposta:
    def __init__(self, corpo, md5=True, last_modified="Mon, 28 Sep 2026 22:51:09 GMT", md5_errado=False):
        self._buf = io.BytesIO(corpo)
        self.headers = email.message.Message()
        self.headers["Content-Length"] = str(len(corpo))
        if last_modified:
            self.headers["Last-Modified"] = last_modified
        if md5:
            digest = hashlib.md5(b"outra coisa" if md5_errado else corpo).digest()
            self.headers["x-goog-hash"] = "crc32c=AAAAAA==,md5=" + base64.b64encode(digest).decode()

    def read(self, n=-1):
        return self._buf.read(n)

    def close(self):
        pass


class BaseTemporaria(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nist-osv-")
        self.db = os.path.join(self.tmp, "bases", "osv.sqlite")
        self.conn = osv_local.connect(self.db, create=True)
        osv_local.init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def importar(self, eco, registros):
        caminho = os.path.join(self.tmp, "%s.zip" % eco)
        with open(caminho, "wb") as fh:
            fh.write(zip_de(registros))
        total = osv_local.importar_zip(self.conn, eco, caminho)
        osv_local.meta_set(self.conn, "eco:%s:atualizado_em" % eco, osv_local.now_iso())
        osv_local.meta_set(self.conn, "eco:%s:registros" % eco, total)
        return total

    def consultar(self, eco, nome, versao):
        base = osv_local.BaseOsvLocal(self.db)
        try:
            regs, nao = base.consultar(eco, nome, versao)
        finally:
            base.close()
        return sorted(r["id"] for r in regs), nao


class TestImportacaoEConsulta(BaseTemporaria):
    def test_consulta_por_versao(self):
        self.importar("npm", [GHSA_QS, MAL_LODASH, RETIRADO,
                              registro("GHSA-lodash", "npm", "lodash", [("introduced", "0"), ("fixed", "4.17.21")])])
        self.assertEqual(self.consultar("npm", "qs", "6.7.0")[0], ["GHSA-hrpp-h998-j3pp"])
        self.assertEqual(self.consultar("npm", "qs", "6.7.3")[0], [])
        self.assertEqual(self.consultar("npm", "lodash", "4.17.20")[0], ["GHSA-lodash", "MAL-2025-0001"])
        self.assertEqual(self.consultar("npm", "lodash", "4.17.21")[0], ["MAL-2025-0001"])
        self.assertEqual(self.consultar("npm", "nao-existe", "1.0.0"), ([], []))

    def test_pypi_normaliza_nome_e_versao(self):
        self.importar("PyPI", [registro("PYSEC-1", "PyPI", "Django", [("introduced", "4.0"), ("fixed", "4.2.2")]),
                               registro("PYSEC-2", "PyPI", "some_pkg", versoes=["1.0", "1.1"])])
        self.assertEqual(self.consultar("PyPI", "django", "4.2.1")[0], ["PYSEC-1"])
        self.assertEqual(self.consultar("PyPI", "Some.Pkg", "1.0.0")[0], ["PYSEC-2"])
        self.assertEqual(self.consultar("PyPI", "django", "4.2.2")[0], [])

    def test_versao_nao_avaliavel_e_informada(self):
        self.importar("npm", [registro("GHSA-x", "npm", "x", [("introduced", "0"), ("fixed", "1.0.0")])])
        self.assertEqual(self.consultar("npm", "x", "banana"), ([], ["GHSA-x"]))

    def test_entrada_de_outro_ecossistema_nao_duplica(self):
        misto = registro("GHSA-m", "npm", "lib", [("introduced", "0")])
        misto["affected"].append({"package": {"ecosystem": "PyPI", "name": "lib"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]})
        self.importar("npm", [misto])
        self.assertEqual(self.consultar("PyPI", "lib", "1.0")[0], [])  # só entra quando o PyPI for importado
        self.importar("PyPI", [misto])
        self.assertEqual(self.consultar("PyPI", "lib", "1.0")[0], ["GHSA-m"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM affected").fetchone()[0], 2)

    def test_reimportacao_troca_o_conteudo_e_limpa_orfaos(self):
        self.importar("npm", [GHSA_QS, MAL_LODASH])
        self.importar("npm", [MAL_LODASH])
        self.assertEqual(self.consultar("npm", "qs", "6.7.0")[0], [])
        ids = {r[0] for r in self.conn.execute("SELECT id FROM vulns")}
        self.assertEqual(ids, {"MAL-2025-0001"})

    def test_zip_corrompido_nao_altera_a_base(self):
        self.importar("npm", [GHSA_QS])
        ruim = os.path.join(self.tmp, "ruim.zip")
        with open(ruim, "wb") as fh:
            fh.write(b"isto nao e zip")
        with self.assertRaises(osv_local.BaseOsvErro):
            osv_local.importar_zip(self.conn, "npm", ruim)
        self.assertEqual(self.consultar("npm", "qs", "6.7.0")[0], ["GHSA-hrpp-h998-j3pp"])

    def test_estado_com_idade(self):
        self.importar("npm", [GHSA_QS])
        antigo = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        osv_local.meta_set(self.conn, "eco:npm:atualizado_em", antigo)
        base = osv_local.BaseOsvLocal(self.db)
        estado = base.estado()
        base.close()
        self.assertGreaterEqual(estado["ecossistemas"]["npm"]["idade_dias"], 9.9)
        self.assertNotIn("PyPI", estado["ecossistemas"])


class TestDownload(BaseTemporaria):
    def setUp(self):
        super().setUp()
        self.downloads = os.path.join(self.tmp, "downloads")
        self.respostas = {}
        self.pedidos = []
        self.orig = download_osv._abrir
        download_osv._abrir = self.abrir_falso

    def tearDown(self):
        download_osv._abrir = self.orig
        super().tearDown()

    def abrir_falso(self, url, **kw):
        self.pedidos.append(url)
        if url not in self.respostas:
            raise download_osv.DownloadErro("HTTP 404 em %s" % url)
        return self.respostas[url]()

    def servir(self, caminho, corpo, **kw):
        self.respostas[download_osv.BASE_URL + "/" + caminho] = lambda: _Resposta(corpo, **kw)

    def test_md5_errado_descarta_o_arquivo(self):
        self.servir("npm/all.zip", zip_de([GHSA_QS]), md5_errado=True)
        with self.assertRaises(download_osv.DownloadErro):
            download_osv.sync_completo(self.conn, "npm", self.downloads, saida=lambda *a: None)
        self.assertEqual(os.listdir(self.downloads), [])
        self.assertIsNone(osv_local.meta_get(self.conn, "eco:npm:corte"))

    def test_sem_md5_publicado_recusa(self):
        self.servir("npm/all.zip", zip_de([GHSA_QS]), md5=False)
        with self.assertRaises(download_osv.DownloadErro):
            download_osv.sync_completo(self.conn, "npm", self.downloads, saida=lambda *a: None)

    def test_completo_e_depois_incremental(self):
        self.servir("npm/all.zip", zip_de([GHSA_QS]))
        download_osv.sync_completo(self.conn, "npm", self.downloads, saida=lambda *a: None)
        self.assertEqual(os.listdir(self.downloads), [])  # o .zip é apagado depois de importado
        self.assertEqual(osv_local.meta_get(self.conn, "eco:npm:corte"), "2026-09-28T16:51:09Z")

        corrigido = dict(GHSA_QS, affected=[{"package": {"ecosystem": "npm", "name": "qs"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "6.7.0"}, {"fixed": "6.7.1"}]}]}])
        novo = registro("GHSA-novo", "npm", "express", [("introduced", "0"), ("fixed", "4.19.2")])
        csv = ("2026-09-29T10:00:00.123456789Z,GHSA-novo\n2026-09-29T09:00:00Z,GHSA-hrpp-h998-j3pp\n"
               "2026-09-28T10:00:00Z,GHSA-antigo-nao-deve-vir\n")
        self.servir("npm/modified_id.csv", csv.encode())
        self.servir("npm/GHSA-novo.json", json.dumps(novo).encode())
        self.servir("npm/GHSA-hrpp-h998-j3pp.json", json.dumps(corrigido).encode())
        download_osv.sync_incremental(self.conn, "npm", self.downloads, saida=lambda *a: None)
        self.assertFalse(any("antigo" in p for p in self.pedidos))
        self.assertEqual(self.consultar("npm", "express", "4.18.2")[0], ["GHSA-novo"])
        self.assertEqual(self.consultar("npm", "qs", "6.7.2")[0], [])  # a correção nova vale
        self.assertEqual(osv_local.meta_get(self.conn, "eco:npm:corte"), "2026-09-29T09:00:00Z")

    def test_falha_no_incremental_nao_avanca_o_corte(self):
        self.servir("npm/all.zip", zip_de([GHSA_QS]))
        download_osv.sync_completo(self.conn, "npm", self.downloads, saida=lambda *a: None)
        self.servir("npm/modified_id.csv", b"2026-09-29T10:00:00Z,GHSA-sumiu\n")
        download_osv.sync_incremental(self.conn, "npm", self.downloads, saida=lambda *a: None)
        self.assertEqual(osv_local.meta_get(self.conn, "eco:npm:corte"), "2026-09-28T16:51:09Z")

    def test_id_estranho_no_csv_e_ignorado(self):
        ids, _ = download_osv.ids_alterados("2026-09-29T10:00:00Z,../../etc/passwd\n2026-09-29T09:00:00Z,GHSA-ok\n",
                                            datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertEqual(ids, ["GHSA-ok"])


class TestScanLocal(BaseTemporaria):
    def setUp(self):
        super().setUp()
        self.raiz = os.path.join(self.tmp, "projeto")
        shutil.copytree(os.path.join(RAIZ, "evals", "auditoria-app-vulneravel", "projeto"), self.raiz)
        self.orig = sca_scan.http_json

        def sem_rede(*a, **kw):
            raise AssertionError("o modo local tentou usar a rede")
        sca_scan.http_json = sem_rede

    def tearDown(self):
        sca_scan.http_json = self.orig
        super().tearDown()

    def test_mesmo_resultado_do_online_sem_rede(self):
        self.importar("npm", [GHSA_QS, MAL_LODASH, RETIRADO])
        self.conn.close()
        resultado = sca_scan.scan(self.raiz, osv_db=self.db)
        self.conn = osv_local.connect(self.db, create=True)
        vulneraveis = {p["nome"]: p for p in resultado["vulneraveis"]}
        qs = vulneraveis["qs"]["vulnerabilidades"]
        self.assertEqual([v["id"] for v in qs], ["GHSA-hrpp-h998-j3pp"])
        self.assertEqual(qs[0]["corrigido_em"], ["6.7.3"])
        self.assertEqual(qs[0]["severidade"]["nota"], 7.5)
        self.assertEqual([p["nome"] for p in resultado["maliciosos"]], ["lodash"])
        self.assertEqual(resultado["consulta"]["modo"], "local")
        self.assertEqual(resultado["consulta"]["status"], "ok")
        self.assertEqual(resultado["consulta"]["pacotes_enviados"], 0)
        self.assertEqual(resultado["base_osv"]["estado"], "disponível")

    def test_ecossistema_ausente_fica_nao_avaliado(self):
        self.importar("PyPI", [registro("PYSEC-1", "PyPI", "x", [("introduced", "0")])])
        self.conn.close()
        resultado = sca_scan.scan(self.raiz, osv_db=self.db)
        self.conn = osv_local.connect(self.db, create=True)
        self.assertEqual(resultado["consulta"]["status"], "parcial")
        self.assertTrue(all(n["motivo"].startswith("ecossistema") for n in resultado["consulta"]["nao_avaliados"]))
        self.assertTrue(any("download_osv.py --ecossistemas npm" in l for l in resultado["limites"]))

    def test_base_ausente(self):
        resultado = sca_scan.scan(self.raiz, osv_db=os.path.join(self.tmp, "nao-existe.sqlite"))
        self.assertEqual(resultado["consulta"]["status"], "indisponivel")
        self.assertIn("download_osv.py", resultado["consulta"]["erros"][0])
        self.assertEqual(resultado["inventario"]["total"], 6)


class TestCaminhos(unittest.TestCase):
    def test_nvd_antiga_e_encontrada_ate_existir_a_nova(self):
        tmp = tempfile.mkdtemp(prefix="nist-bases-")
        self.addCleanup(shutil.rmtree, tmp, True)
        antiga = os.path.join(tmp, "velha", "nvd.sqlite")
        os.makedirs(os.path.dirname(antiga))
        open(antiga, "w").close()
        with mock.patch.dict(os.environ, {"NIST_AEGIS_HOME": os.path.join(tmp, "home")}), \
                mock.patch.object(bases, "nvd_legacy", return_value=antiga):
            self.assertEqual(bases.resolve_nvd(), antiga)
            os.makedirs(bases.bases_dir())
            open(bases.nvd_default(), "w").close()
            self.assertEqual(bases.resolve_nvd(), bases.nvd_default())
            self.assertEqual(bases.resolve_nvd("~/x.sqlite"), os.path.abspath(os.path.expanduser("~/x.sqlite")))
            self.assertEqual(bases.osv_default(), os.path.join(tmp, "home", "bases", "osv.sqlite"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
