"""Testes do inventario.py. Só biblioteca padrão; usa git se estiver instalado.

Rode com:  python tests/test_inventario.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "skills", "audit", "scripts"))

import inventario  # noqa: E402

TEM_GIT = shutil.which("git") is not None

# Valores falsos montados por concatenação: o arquivo de teste não contém nenhuma sequência com
# formato de chave real, só o projeto temporário que o teste cria.
CHAVE_AWS_FALSA = "AKIA" + "ABCDEFGHIJKLMNOP"
CHAVE_AWS_EXCLUIDA = "AKIA" + "Z" * 16


def escrever(base, relativo, conteudo):
    caminho = os.path.join(base, relativo)
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(conteudo)
    return caminho


class Projeto(unittest.TestCase):
    def setUp(self):
        self.raiz = tempfile.mkdtemp(prefix="nist-inv-")
        escrever(self.raiz, "src/app.js", "const k = '" + CHAVE_AWS_FALSA + "';\nconst s = 'sk_live_" + "a1b2c3d4e5f6g7h8i9j0" + "';\n")
        escrever(self.raiz, "src/config.py", "password = 'Sup3rS3cretValue!'\nsenha = 'changeme123'\n"
                 "PAYMENT_API_SECRET = 'nstcanary_9f2c7e1a4b8d6f3e0a5c'\ntokenizer = 'bert-base-uncased'\n")
        escrever(self.raiz, "src/doc.md", "Use a chave AKIAIOSFODNN7EXAMPLE no exemplo.\npassword = 'ignorado-em-doc'\n")
        escrever(self.raiz, ".env", "DATABASE_URL=postgres://app:SenhaForte9@db.interno:5432/app\n")
        escrever(self.raiz, "node_modules/x/index.js", "const t = '" + CHAVE_AWS_EXCLUIDA + "';\n")
        escrever(self.raiz, "package.json", "{}\n")
        escrever(self.raiz, "package-lock.json", "{}\n")
        escrever(self.raiz, "Dockerfile", "FROM node:20\n")
        escrever(self.raiz, ".github/workflows/ci.yml", "on: push\n")
        escrever(self.raiz, "CLAUDE.md", "Instruções​ do projeto\n")
        escrever(self.raiz, "native/lib.c", "int main(void){return 0;}\n")
        escrever(self.raiz, "deploy/k8s.yaml", "apiVersion: v1\nkind: Service\n")
        with open(os.path.join(self.raiz, "logo.png"), "wb") as fh:
            fh.write(b"\x89PNG\x00\x00")

    def tearDown(self):
        shutil.rmtree(self.raiz, ignore_errors=True)

    def git(self, *args):
        subprocess.run(["git"] + list(args), cwd=self.raiz, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class TestInventario(Projeto):
    def test_contagem_exclusoes_e_superficies(self):
        r = inventario.inventory(self.raiz)
        self.assertIn("node_modules", r["diretorios_excluidos"])
        self.assertNotIn("node_modules/x/index.js", r["elegiveis"])
        self.assertNotIn("package-lock.json", r["elegiveis"])
        self.assertNotIn("logo.png", r["elegiveis"])
        self.assertNotIn("src/doc.md", r["elegiveis"])
        self.assertIn("package.json", r["elegiveis"])
        self.assertEqual(r["arquivos_elegiveis"], len(r["elegiveis"]))
        self.assertEqual(r["infra"]["dockerfiles"], ["Dockerfile"])
        self.assertEqual(r["infra"]["ci"], [".github/workflows/ci.yml"])
        self.assertEqual(r["infra"]["kubernetes"], ["deploy/k8s.yaml"])
        self.assertTrue(r["c_cpp"]["fora_de_escopo"])
        self.assertIn("CLAUDE.md", r["configuracao_de_agente"])
        self.assertEqual(r["unicode_oculto"][0]["arquivo"], "CLAUDE.md")

    def test_segredos_mascarados_sem_valor(self):
        r = inventario.inventory(self.raiz)
        texto = json.dumps(r["segredos_candidatos"], ensure_ascii=False)
        for valor in (CHAVE_AWS_FALSA, "a1b2c3d4e5f6g7h8i9j0", "Sup3rS3cretValue!", "SenhaForte9"):
            self.assertNotIn(valor, texto)
        tipos = {(h["arquivo"], h["tipo"]) for h in r["segredos_candidatos"]}
        self.assertIn(("src/app.js", "chave de acesso AWS"), tipos)
        self.assertIn(("src/app.js", "chave do Stripe"), tipos)
        self.assertIn((".env", "URL com usuário e senha"), tipos)
        self.assertIn(("src/config.py", "valor atribuído a 'password'"), tipos)
        self.assertIn(("src/config.py", "valor atribuído a 'payment_api_secret'"), tipos)
        self.assertNotIn(("src/config.py", "valor atribuído a 'senha'"), tipos)  # changeme é exemplo
        self.assertNotIn(("src/config.py", "valor atribuído a 'tokenizer'"), tipos)
        self.assertNotIn("9f2c7e1a4b8d6f3e0a5c", texto)
        aws = [h for h in r["segredos_candidatos"] if h["tipo"] == "chave de acesso AWS" and h["arquivo"] == "src/app.js"][0]
        self.assertTrue(aws["mascara"].startswith("AKIA…(20"))

    def test_exemplo_documentado_e_marcado(self):
        r = inventario.inventory(self.raiz)
        doc = [h for h in r["segredos_candidatos"] if h["arquivo"] == "src/doc.md"]
        self.assertEqual(len(doc), 1)  # a atribuição genérica não vale em documentação
        self.assertIsNotNone(doc[0]["exemplo"])

    def test_base_de_diff_invalida_e_recusada(self):
        with self.assertRaises(ValueError):
            inventario.inventory(self.raiz, diff_base="--output=/tmp/x")
        with self.assertRaises(ValueError):
            inventario.inventory(self.raiz, subdir="../fora")

    def test_subdiretorio(self):
        r = inventario.inventory(self.raiz, subdir="src")
        self.assertEqual(r["escopo"]["tipo"], "subdiretorio")
        self.assertTrue(all(a.startswith("src/") for a in r["elegiveis"]))

    @unittest.skipUnless(TEM_GIT, "git não instalado")
    def test_git_versionados_e_diff(self):
        self.git("init", "-q", "-b", "main")
        self.git("add", "src/app.js", "package.json")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "a")
        self.git("checkout", "-q", "-b", "feature")
        escrever(self.raiz, "src/novo.js", "module.exports = 1;\n")
        self.git("add", "src/novo.js")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "b")
        r = inventario.inventory(self.raiz, diff_base="main")
        self.assertTrue(r["git"]["repositorio"])
        self.assertIn("src/app.js", r["versionados"])
        self.assertNotIn(".env", r["versionados"])
        env = [h for h in r["segredos_candidatos"] if h["arquivo"] == ".env"][0]
        app = [h for h in r["segredos_candidatos"] if h["arquivo"] == "src/app.js"][0]
        self.assertFalse(env["versionado"])
        self.assertTrue(app["versionado"])
        self.assertEqual(r["escopo"]["tipo"], "diff")
        self.assertEqual(r["escopo"]["arquivos"], ["src/novo.js"])

    def test_main_grava_json(self):
        saida = os.path.join(self.raiz, "security-audit", ".trabalho", "inventario.json")
        self.assertEqual(inventario.main(["--raiz", self.raiz, "--saida", saida]), 0)
        with open(saida, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["ferramenta"], "inventario")
        # a própria pasta do relatório não entra no inventário
        r = inventario.inventory(self.raiz)
        self.assertFalse(any(a.startswith("security-audit/") for a in r["elegiveis"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
