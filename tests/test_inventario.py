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
from unittest import mock

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


def criar_link(alvo, link):
    try:
        os.symlink(alvo, link)
        return True
    except (OSError, NotImplementedError):
        return False


class TestEndurecimento(Projeto):
    @unittest.skipUnless(TEM_GIT, "git não instalado")
    def test_git_nao_faz_fetch_preguicoso_de_partial_clone(self):
        """Partial clone com objeto ausente: o git buscaria o objeto pelo remote e rodaria o
        core.sshCommand do repositório. O inventário não pode disparar isso."""
        self.git("init", "-q", "-b", "main")
        self.git("add", "src/app.js")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "a")
        self.git("checkout", "-q", "-b", "feature")
        self.git("add", "package.json")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "b")
        arvore = subprocess.run(["git", "rev-parse", "main^{tree}"], cwd=self.raiz, check=True,
                                stdout=subprocess.PIPE).stdout.decode().strip()
        objeto = os.path.join(self.raiz, ".git", "objects", arvore[:2], arvore[2:])
        os.chmod(objeto, 0o644)  # o git grava objeto como somente leitura
        os.remove(objeto)
        marcador = os.path.join(self.raiz, "EXECUTOU")
        python = sys.executable.replace("\\", "/")
        comando = '"%s" -c "open(r\'%s\', \'w\').close()"' % (python, marcador.replace("\\", "/"))
        for chave, valor in (("core.repositoryformatversion", "1"), ("extensions.partialClone", "origin"),
                             ("remote.origin.url", "ssh://example.invalid/x"), ("remote.origin.promisor", "true"),
                             ("core.sshCommand", comando)):
            self.git("config", chave, valor)
        # controle: sem as proteções, o ataque funciona neste ambiente
        subprocess.run(["git", "diff", "--name-only", "main...HEAD"], cwd=self.raiz,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        if not os.path.exists(marcador):
            self.skipTest("o git deste ambiente não fez o fetch preguiçoso nem sem proteção")
        os.remove(marcador)
        r = inventario.inventory(self.raiz, diff_base="main")
        self.assertFalse(os.path.exists(marcador), "o inventário executou o core.sshCommand do repositório")
        self.assertIsNotNone(r["git"]["erro"])  # o diff falha sem o objeto, e isso fica registrado

    @unittest.skipUnless(TEM_GIT, "git não instalado")
    def test_git_plantado_na_raiz_nao_e_usado(self):
        nome = "git.exe" if os.name == "nt" else "git"
        falso = escrever(self.raiz, nome, "#!/bin/sh\nexit 0\n")
        os.chmod(falso, 0o755)
        caminho = os.pathsep.join([self.raiz, ".", os.environ.get("PATH", "")])
        with mock.patch.dict(os.environ, {"PATH": caminho}):
            escolhido = inventario.git_executable(self.raiz)
        self.assertFalse(inventario._inside(escolhido, self.raiz), escolhido)
        self.assertTrue(os.path.isabs(escolhido))

    def test_subdiretorio_com_prefixo_igual_ao_da_raiz_e_recusado(self):
        vizinho = self.raiz + "2"
        os.makedirs(vizinho)
        try:
            with self.assertRaises(ValueError):
                inventario.inventory(self.raiz, subdir="../" + os.path.basename(vizinho))
        finally:
            shutil.rmtree(vizinho, ignore_errors=True)

    def test_link_simbolico_nao_e_seguido(self):
        fora = tempfile.mkdtemp(prefix="nist-fora-")
        self.addCleanup(shutil.rmtree, fora, True)
        alvo = escrever(fora, "credentials", "aws_secret_access_key = '" + "Qm9" + "vZ3pWx7Lk2Rt8Yp4" + "'\n")
        if not criar_link(alvo, os.path.join(self.raiz, "src", "link.py")):
            self.skipTest("este ambiente não permite criar link simbólico")
        r = inventario.inventory(self.raiz)
        self.assertIn("src/link.py", r["links_simbolicos"])
        self.assertNotIn("src/link.py", r["elegiveis"])
        self.assertFalse([h for h in r["segredos_candidatos"] if h["arquivo"] == "src/link.py"])


class TestSegredosSemAspas(Projeto):
    def test_config_sem_aspas_e_detectado_e_mascarado(self):
        valor_env = "Hx7" + "pQ2vLm9Tz4"
        valor_yaml = "Rw5" + "nB8kJc3Ys6"
        escrever(self.raiz, ".env.production", "DB_PASSWORD=%s\nTOKEN_TTL=3600000\nAPI_KEY=${API_KEY}\n" % valor_env)
        escrever(self.raiz, "config/app.yaml", "db:\n  password: %s  # produção\n  token_ttl: 3600\n"
                 "  secret: $VAULT_SECRET\n  api_key: ENC[AES256_GCM,data:abc]\n" % valor_yaml)
        escrever(self.raiz, "src/servico.py", "password = obter_senha_do_cofre()\n")
        r = inventario.inventory(self.raiz)
        texto = json.dumps(r["segredos_candidatos"], ensure_ascii=False)
        self.assertNotIn(valor_env, texto)
        self.assertNotIn(valor_yaml, texto)
        achados = {(h["arquivo"], h["linha"], h["tipo"]) for h in r["segredos_candidatos"]}
        self.assertIn((".env.production", 1, "valor atribuído a 'db_password'"), achados)
        self.assertIn(("config/app.yaml", 2, "valor atribuído a 'password'"), achados)
        arquivos_linhas = {(a, l) for a, l, _ in achados}
        for falso_positivo in ((".env.production", 2), (".env.production", 3), ("config/app.yaml", 3),
                               ("config/app.yaml", 4), ("config/app.yaml", 5), ("src/servico.py", 1)):
            self.assertNotIn(falso_positivo, arquivos_linhas)

    def test_linha_informada_ignora_quebras_que_nao_sao_newline(self):
        escrever(self.raiz, "src/x.py", "a = 1\x0cb = 2 c = 3\npassword = '" + "Tq4" + "mW9xZp2Lr7" + "'\n")
        r = inventario.inventory(self.raiz)
        linha = [h["linha"] for h in r["segredos_candidatos"] if h["arquivo"] == "src/x.py"]
        self.assertEqual(linha, [2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
