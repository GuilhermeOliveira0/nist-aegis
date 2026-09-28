"""Testes dos scripts de CVE (skills/cve/scripts). Só biblioteca padrão.

Rode com:  python tests/test_cve_scripts.py
"""

import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(RAIZ, "skills", "cve", "scripts")
sys.path.insert(0, SCRIPTS)

import download_db  # noqa: E402
import local_lookup  # noqa: E402
import nvd_common  # noqa: E402
import nvd_lookup  # noqa: E402


# ---------------------------------------------------------------- registros de teste

def _desc(texto):
    return [{"lang": "en", "value": texto}]


def _metrica(versao, nota, nivel, fonte="nvd@nist.gov", tipo="Primary"):
    return {
        "source": fonte,
        "type": tipo,
        "cvssData": {
            "version": versao,
            "baseScore": nota,
            "baseSeverity": nivel,
            "vectorString": "CVSS:%s/AV:N/AC:L/PR:N/UI:N" % versao,
        },
    }


def _match(criteria, match_id, vulneravel=True, **faixa):
    item = {"vulnerable": vulneravel, "criteria": criteria, "matchCriteriaId": match_id}
    item.update(faixa)
    return item


LOG4SHELL = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "lastModified": "2026-08-11T00:00:00.000",
    "vulnStatus": "Analyzed",
    "cisaExploitAdd": "2021-12-10",
    "descriptions": _desc("Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."),
    "metrics": {"cvssMetricV31": [_metrica("3.1", 10.0, "CRITICAL")]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
        _match("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "03FA5E81",
               versionStartIncluding="2.0.1", versionEndExcluding="2.3.1"),
        _match("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "AED3D5EC",
               versionStartIncluding="2.4.0", versionEndExcluding="2.12.2"),
        _match("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "D31D423D",
               versionStartIncluding="2.13.0", versionEndExcluding="2.15.0"),
        _match("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", "B9000001"),
    ]}]}],
}

ZOOM_EM_WINDOWS = {
    "id": "CVE-2023-49647",
    "published": "2024-01-12T00:00:00.000",
    "lastModified": "2024-01-20T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("Improper access control in Zoom Clients for Windows."),
    "metrics": {"cvssMetricV31": [
        _metrica("3.1", 9.8, "CRITICAL", fonte="security@zoom.us", tipo="Secondary"),
        _metrica("3.1", 6.5, "MEDIUM"),
    ]},
    "configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [
            _match("cpe:2.3:a:zoom:meetings:*:*:*:*:*:*:*:*", "Z0000001", versionEndExcluding="5.16.5")]},
        {"operator": "OR", "cpeMatch": [
            _match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "W0000001", vulneravel=False)]},
    ]}],
}

WINDOWS_DE_VERDADE = {
    "id": "CVE-2024-00001",
    "published": "2024-02-01T00:00:00.000",
    "lastModified": "2024-02-02T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("Elevation of privilege in the Windows kernel."),
    "metrics": {"cvssMetricV31": [_metrica("3.1", 7.8, "HIGH")]},
    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
        _match("cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*", "W0000002")]}]}],
}

WS = {
    "id": "CVE-2024-37890",
    "published": "2024-06-17T00:00:00.000",
    "lastModified": "2026-06-17T00:00:00.000",
    "vulnStatus": "Deferred",
    "descriptions": _desc("ws is an open source WebSocket client and server for Node.js. A request "
                          "with a number of headers exceeding the threshold crashes the server."),
    "metrics": {"cvssMetricV31": [
        _metrica("3.1", 7.5, "HIGH", fonte="security-advisories@github.com", tipo="Secondary")]},
}

STATD_1999 = {
    "id": "CVE-1999-0018",
    "published": "1999-01-01T00:00:00.000",
    "lastModified": "2008-09-09T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("Buffer overflow in statd allows root privileges."),
    "metrics": {"cvssMetricV2": [{
        "source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
        "cvssData": {"version": "2.0", "baseScore": 10.0, "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
    }]},
}

SO_V4 = {
    "id": "CVE-2026-45041",
    "published": "2026-05-01T00:00:00.000",
    "lastModified": "2026-05-02T00:00:00.000",
    "vulnStatus": "Awaiting Analysis",
    "descriptions": _desc("rustfs allows unauthenticated access to the admin API."),
    "metrics": {"cvssMetricV40": [
        _metrica("4.0", 8.7, "HIGH", fonte="security-advisories@github.com", tipo="Secondary")]},
}

REJEITADO = {
    "id": "CVE-2020-99999",
    "published": "2020-01-01T00:00:00.000",
    "lastModified": "2020-02-01T00:00:00.000",
    "vulnStatus": "Rejected",
    "descriptions": _desc("Rejected reason: this candidate is a duplicate of a websocket issue in ws."),
    "metrics": {},
}

SEM_NOTA = {
    "id": "CVE-2026-50000",
    "published": "2026-06-01T00:00:00.000",
    "lastModified": "2026-06-01T00:00:00.000",
    "vulnStatus": "Received",
    "descriptions": _desc("In the Linux kernel, the following vulnerability in ws handling has been resolved."),
    "metrics": {},
}

PYTHON_JOSE = {
    "id": "CVE-2024-33663",
    "published": "2024-04-26T00:00:00.000",
    "lastModified": "2024-05-01T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("python-jose through 3.3.0 has algorithm confusion with OpenSSH ECDSA keys."),
    "metrics": {"cvssMetricV31": [_metrica("3.1", 6.5, "MEDIUM")]},
}

HIFEN_SEM_QUEBRA = {
    "id": "CVE-2025-11111",
    "published": "2025-03-01T00:00:00.000",
    "lastModified": "2025-03-01T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("Pacote hifen‑teste ≤ 1.2 permite leitura → escrita."),
    "metrics": {"cvssMetricV31": [_metrica("3.1", 5.0, "MEDIUM")]},
}

CEM_POR_CENTO = {
    "id": "CVE-2025-22222",
    "published": "2025-04-01T00:00:00.000",
    "lastModified": "2025-04-01T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("A crafted request causes 100% CPU usage."),
    "metrics": {"cvssMetricV31": [_metrica("3.1", 5.3, "MEDIUM")]},
}

MIL_REQUESTS = {
    "id": "CVE-2025-33333",
    "published": "2025-04-02T00:00:00.000",
    "lastModified": "2025-04-02T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": _desc("Sending 1000 requests exhausts memory."),
    "metrics": {"cvssMetricV31": [_metrica("3.1", 5.3, "MEDIUM")]},
}

TODOS = [LOG4SHELL, ZOOM_EM_WINDOWS, WINDOWS_DE_VERDADE, WS, STATD_1999, SO_V4, REJEITADO,
         SEM_NOTA, PYTHON_JOSE, HIFEN_SEM_QUEBRA, CEM_POR_CENTO, MIL_REQUESTS]


# ---------------------------------------------------------------- utilitários

class BaseTemporaria(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="nist-teste-")
        self.db = os.path.join(self.dir, "nvd.sqlite")
        conn = nvd_common.connect(self.db)
        nvd_common.init_schema(conn)
        for cve in TODOS:
            nvd_common.upsert_cve(conn, cve)
        nvd_common.meta_set(conn, "complete", "1")
        nvd_common.meta_set(conn, "last_sync", "2026-09-28T12:00:00.000Z")
        nvd_common.meta_set(conn, "data_version", str(nvd_common.DATA_VERSION))
        conn.commit()
        conn.close()

    def consultar(self, *argv):
        args = local_lookup.build_parser().parse_args(["--db", self.db] + list(argv))
        conn = nvd_common.connect(self.db, create=False, readonly=True)
        try:
            linhas, total = local_lookup.query_rows(conn, args)
        finally:
            conn.close()
        return [linha["cve_id"] for linha in linhas], total

    def rodar_script(self, script, *argv, env_extra=None):
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, script)] + list(argv),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120,
        )


def _cpes_de(db, cve_id):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM cpes WHERE cve_id = ?", (cve_id,))]
    finally:
        conn.close()


# ---------------------------------------------------------------- extração

class TestExtracao(unittest.TestCase):
    def test_cpe_mantem_faixas_com_o_mesmo_criteria(self):
        linhas = nvd_common.extract_cpes(LOG4SHELL)
        faixas = [(l["version_start"], l["version_end"]) for l in linhas
                  if l["criteria"] == "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"]
        self.assertEqual(faixas, [("2.0.1", "2.3.1"), ("2.4.0", "2.12.2"), ("2.13.0", "2.15.0")])

    def test_cpe_grava_match_id_versao_update_e_vulnerable(self):
        linhas = {l["match_id"]: l for l in nvd_common.extract_cpes(LOG4SHELL)}
        self.assertEqual(linhas["B9000001"]["cpe_version"], "2.0")
        self.assertEqual(linhas["B9000001"]["cpe_update"], "beta9")
        self.assertEqual(linhas["03FA5E81"]["vulnerable"], 1)
        plataforma = [l for l in nvd_common.extract_cpes(ZOOM_EM_WINDOWS)
                      if l["vendor_product"] == "microsoft:windows"]
        self.assertEqual(plataforma[0]["vulnerable"], 0)

    def test_metrica_v40_entra_como_fallback(self):
        m = nvd_common.extract_metrics(SO_V4)
        self.assertEqual((m["version"], m["score"], m["severity"]), ("4.0", 8.7, "HIGH"))
        self.assertEqual(m["rank"], nvd_common.SEVERITY_RANK["HIGH"])

    def test_metrica_exibe_primary_e_filtra_pela_maior(self):
        m = nvd_common.extract_metrics(ZOOM_EM_WINDOWS)
        self.assertEqual((m["score"], m["severity"], m["type"]), (6.5, "MEDIUM", "Primary"))
        self.assertEqual(m["rank"], nvd_common.SEVERITY_RANK["CRITICAL"])

    def test_metrica_v31_tem_prioridade_sobre_v40(self):
        cve = dict(SO_V4)
        cve["metrics"] = {"cvssMetricV40": [_metrica("4.0", 9.3, "CRITICAL")],
                          "cvssMetricV31": [_metrica("3.1", 7.5, "HIGH")]}
        self.assertEqual(nvd_common.extract_metrics(cve)["version"], "3.1")

    def test_kev(self):
        self.assertEqual(nvd_common.extract_kev(LOG4SHELL), "2021-12-10")
        self.assertIsNone(nvd_common.extract_kev(WS))


# ---------------------------------------------------------------- base e esquema

class TestBase(unittest.TestCase):
    def test_upsert_sem_raw_preserva_raw_existente(self):
        with tempfile.TemporaryDirectory() as d:
            conn = nvd_common.connect(os.path.join(d, "b.sqlite"))
            nvd_common.init_schema(conn)
            nvd_common.upsert_cve(conn, WS, store_raw=True)
            nvd_common.upsert_cve(conn, WS, store_raw=False)
            raw = conn.execute("SELECT raw FROM cves WHERE cve_id = ?", (WS["id"],)).fetchone()[0]
            conn.close()
        self.assertIsNotNone(raw)

    def test_migracao_de_base_antiga(self):
        antigo = """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE cves (cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT,
            vuln_status TEXT, description TEXT, description_lc TEXT, cvss_version TEXT,
            base_score REAL, base_severity TEXT, severity_rank INTEGER, vector_string TEXT,
            cwes TEXT, raw TEXT);
        CREATE TABLE cpes (cve_id TEXT, criteria TEXT, vendor_product TEXT, version_start TEXT,
            version_start_op TEXT, version_end TEXT, version_end_op TEXT);
        INSERT INTO meta VALUES ('schema_version', '1');
        INSERT INTO cves (cve_id, description) VALUES ('CVE-2000-0001', 'antigo');
        """
        with tempfile.TemporaryDirectory() as d:
            caminho = os.path.join(d, "velha.sqlite")
            bruto = sqlite3.connect(caminho)
            bruto.executescript(antigo)
            bruto.close()
            conn = nvd_common.connect(caminho)
            nvd_common.init_schema(conn)
            colunas_cpes = {r[1] for r in conn.execute("PRAGMA table_info(cpes)")}
            colunas_cves = {r[1] for r in conn.execute("PRAGMA table_info(cves)")}
            antigo_ok = conn.execute("SELECT description FROM cves WHERE cve_id='CVE-2000-0001'").fetchone()[0]
            versao = nvd_common.meta_get(conn, "schema_version")
            conn.close()
        self.assertTrue({"match_id", "vulnerable", "cpe_version", "cpe_update", "target_sw"} <= colunas_cpes)
        self.assertTrue({"kev_added", "cvss_source", "cvss_type"} <= colunas_cves)
        self.assertEqual(antigo_ok, "antigo")
        self.assertEqual(versao, str(nvd_common.SCHEMA_VERSION))


# ---------------------------------------------------------------- consulta local

class TestConsultaLocal(BaseTemporaria):
    def test_keyword_casa_palavra_inteira(self):
        ids, _ = self.consultar("--keyword", "ws")
        self.assertIn("CVE-2024-37890", ids)
        self.assertNotIn("CVE-1999-0018", ids)  # "allows"
        self.assertNotIn("CVE-2024-00001", ids)  # "Windows"

    def test_keyword_normaliza_separadores(self):
        self.assertIn("CVE-2024-33663", self.consultar("--keyword", "python_jose")[0])
        self.assertIn("CVE-2024-33663", self.consultar("--keyword", "python-jose")[0])

    def test_keyword_com_porcento_e_literal(self):
        ids, _ = self.consultar("--keyword", "100%")
        self.assertIn("CVE-2025-22222", ids)
        self.assertNotIn("CVE-2025-33333", ids)

    def test_rejeitados_ficam_fora_por_padrao(self):
        self.assertNotIn("CVE-2020-99999", self.consultar("--keyword", "ws")[0])
        self.assertIn("CVE-2020-99999", self.consultar("--keyword", "ws", "--incluir-rejeitados")[0])

    def test_sem_nota_nao_some_com_min_severity(self):
        ids, _ = self.consultar("--keyword", "ws", "--min-severity", "MEDIUM")
        self.assertIn("CVE-2026-50000", ids)
        ids, _ = self.consultar("--keyword", "ws", "--min-severity", "MEDIUM", "--excluir-sem-nota")
        self.assertNotIn("CVE-2026-50000", ids)

    def test_v40_passa_no_filtro_de_severidade(self):
        self.assertIn("CVE-2026-45041", self.consultar("--keyword", "rustfs", "--min-severity", "HIGH")[0])

    def test_filtro_usa_a_maior_nota_entre_primary_e_secondary(self):
        self.assertIn("CVE-2023-49647", self.consultar("--keyword", "zoom", "--min-severity", "CRITICAL")[0])

    def test_product_ignora_plataforma_nao_vulneravel(self):
        ids, _ = self.consultar("--product", "microsoft:windows")
        self.assertIn("CVE-2024-00001", ids)
        self.assertNotIn("CVE-2023-49647", ids)

    def test_total_informa_truncamento(self):
        ids, total = self.consultar("--keyword", "ws", "--limit", "1")
        self.assertEqual(len(ids), 1)
        self.assertGreater(total, 1)

    def test_ordena_critica_v3_antes_de_v2_nota_10(self):
        ids, _ = self.consultar("--keyword", "log4j")
        self.assertEqual(ids[0], "CVE-2021-44228")


# ---------------------------------------------------------------- execução dos scripts

class TestExecucao(BaseTemporaria):
    def test_saida_nao_quebra_com_caractere_fora_do_cp1252(self):
        r = self.rodar_script("local_lookup.py", "--db", self.db, "--keyword", "hifen-teste")
        self.assertNotIn(b"Traceback", r.stderr)
        self.assertEqual(r.returncode, 0)
        r = self.rodar_script("local_lookup.py", "--db", self.db, "--keyword", "hifen-teste", "--json")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout.decode("utf-8"))["resultados"][0]["cve_id"], "CVE-2025-11111")

    def test_codigos_de_saida(self):
        self.assertEqual(self.rodar_script("local_lookup.py", "--db", self.db, "--keyword", "zzzqqq").returncode, 1)
        self.assertEqual(self.rodar_script("local_lookup.py", "--db", self.db).returncode, 2)
        self.assertEqual(self.rodar_script("local_lookup.py", "--db", self.db, "--keyword", "ws", "--limit", "0").returncode, 2)
        ausente = os.path.join(self.dir, "nao-existe.sqlite")
        self.assertEqual(self.rodar_script("local_lookup.py", "--db", ausente, "--stats").returncode, 3)

    def test_stats_sinaliza_base_incompleta(self):
        conn = nvd_common.connect(self.db)
        nvd_common.meta_set(conn, "complete", "0")
        conn.execute("DELETE FROM meta WHERE key = 'last_sync'")
        conn.commit()
        conn.close()
        r = self.rodar_script("local_lookup.py", "--db", self.db, "--stats", "--json")
        estado = json.loads(r.stdout.decode("utf-8"))["estado"]
        self.assertIn("INCOMPLETA", estado)


# ---------------------------------------------------------------- download

class _Paginas:
    """Substitui request_json devolvendo páginas prontas ou levantando erro."""

    def __init__(self, respostas):
        self.respostas = list(respostas)
        self.chamadas = []

    def __call__(self, params, key, *a, **kw):
        self.chamadas.append(dict(params))
        resposta = self.respostas.pop(0)
        if isinstance(resposta, Exception):
            raise resposta
        return resposta


def _pagina(cves, total):
    return {"totalResults": total, "vulnerabilities": [{"cve": c} for c in cves]}


class TestDownload(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="nist-dl-")
        self.conn = nvd_common.connect(os.path.join(self.dir, "b.sqlite"))
        nvd_common.init_schema(self.conn)
        self.orig = (download_db.request_json, download_db.PAGE_SIZE, download_db.SLEEP_WITH_KEY,
                     download_db.SLEEP_NO_KEY, download_db.now_utc)
        download_db.PAGE_SIZE = 2
        download_db.SLEEP_WITH_KEY = download_db.SLEEP_NO_KEY = 0

    def tearDown(self):
        (download_db.request_json, download_db.PAGE_SIZE, download_db.SLEEP_WITH_KEY,
         download_db.SLEEP_NO_KEY, download_db.now_utc) = self.orig
        self.conn.close()

    def test_404_no_meio_nao_marca_base_completa(self):
        download_db.request_json = _Paginas([_pagina([WS, LOG4SHELL], 5),
                                             nvd_common.NvdRequestError("HTTP 404")])
        with self.assertRaises(nvd_common.NvdRequestError):
            download_db.full_download(self.conn, None, True)
        self.assertNotEqual(nvd_common.meta_get(self.conn, "complete"), "1")
        self.assertIsNone(nvd_common.meta_get(self.conn, "last_sync"))

    def test_pagina_curta_antes_do_fim_e_erro(self):
        download_db.request_json = _Paginas([_pagina([WS, LOG4SHELL], 5), _pagina([SO_V4], 5)])
        with self.assertRaises(nvd_common.NvdRequestError):
            download_db.full_download(self.conn, None, True)
        self.assertNotEqual(nvd_common.meta_get(self.conn, "complete"), "1")

    def test_last_sync_e_a_hora_de_inicio(self):
        inicio = datetime(2026, 9, 28, 10, 0, 0, tzinfo=timezone.utc)
        fim = datetime(2026, 9, 28, 11, 30, 0, tzinfo=timezone.utc)
        horas = [inicio, fim, fim, fim]
        download_db.now_utc = lambda: horas.pop(0) if horas else fim
        download_db.request_json = _Paginas([_pagina([WS, LOG4SHELL], 3), _pagina([SO_V4], 3)])
        download_db.full_download(self.conn, None, True)
        self.assertEqual(nvd_common.meta_get(self.conn, "last_sync"), "2026-09-28T10:00:00.000Z")
        self.assertEqual(nvd_common.meta_get(self.conn, "complete"), "1")

    def test_reindex_reaplica_a_extracao(self):
        nvd_common.upsert_cve(self.conn, LOG4SHELL)
        self.conn.execute("DELETE FROM cpes")
        nvd_common.meta_set(self.conn, "data_version", "1")
        self.conn.commit()
        download_db.reindex(self.conn, batch=1)
        faixas = self.conn.execute(
            "SELECT COUNT(*) FROM cpes WHERE cve_id = ? AND criteria LIKE 'cpe:2.3:a:apache:log4j:*%'",
            (LOG4SHELL["id"],)).fetchone()[0]
        self.assertEqual(faixas, 3)
        self.assertEqual(nvd_common.meta_get(self.conn, "data_version"), str(nvd_common.DATA_VERSION))


# ---------------------------------------------------------------- API da NVD

class TestConsultaApi(unittest.TestCase):
    def setUp(self):
        self.orig = (nvd_lookup.request_json, nvd_lookup.PAGE_SIZE, nvd_lookup.SLEEP_WITH_KEY,
                     nvd_lookup.SLEEP_NO_KEY)
        nvd_lookup.PAGE_SIZE = 2
        nvd_lookup.SLEEP_WITH_KEY = nvd_lookup.SLEEP_NO_KEY = 0

    def tearDown(self):
        (nvd_lookup.request_json, nvd_lookup.PAGE_SIZE, nvd_lookup.SLEEP_WITH_KEY,
         nvd_lookup.SLEEP_NO_KEY) = self.orig

    def _rodar(self, *argv):
        saida = io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(io.StringIO()):
            codigo = nvd_lookup.main(list(argv))
        return codigo, saida.getvalue()

    def test_pagina_tudo_antes_de_filtrar(self):
        antigo = dict(STATD_1999, id="CVE-2007-0001")
        nvd_lookup.request_json = _Paginas([_pagina([antigo, PYTHON_JOSE], 3), _pagina([LOG4SHELL], 3)])
        codigo, saida = self._rodar("--keyword", "x", "--min-severity", "CRITICAL", "--json")
        self.assertEqual(codigo, 0)
        self.assertIn("CVE-2021-44228", saida)

    def test_rejeitado_fica_fora(self):
        nvd_lookup.request_json = _Paginas([_pagina([REJEITADO, WS], 2)])
        codigo, saida = self._rodar("--keyword", "ws", "--json")
        self.assertNotIn("CVE-2020-99999", saida)
        self.assertIn("CVE-2024-37890", saida)

    def test_404_e_erro_e_nao_sem_resultado(self):
        nvd_lookup.request_json = _Paginas([nvd_common.NvdRequestError("HTTP 404")])
        codigo, _ = self._rodar("--cve", "CVE-2021-4422X")
        self.assertEqual(codigo, nvd_common.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
