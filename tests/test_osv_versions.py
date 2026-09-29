"""Testes dos comparadores de versão e da avaliação de faixa do OSV. Só biblioteca padrão.

Rode com:  python tests/test_osv_versions.py

As sequências vêm das especificações: SemVer 2.0 (item 11), PEP 440 (exemplo de ordenação),
ComparableVersionTest do Maven. Cada lista está em ordem estritamente crescente.
"""

import os
import sys
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "skills", "cve", "scripts"))

import osv_versions as ov  # noqa: E402


class Ordem(unittest.TestCase):
    def crescente(self, key, versoes):
        for a, b in zip(versoes, versoes[1:]):
            self.assertLess(key(a), key(b), "%s deveria vir antes de %s" % (a, b))

    def iguais(self, key, *versoes):
        for v in versoes[1:]:
            self.assertEqual(key(versoes[0]), key(v), "%s deveria ser igual a %s" % (versoes[0], v))


class TestSemver(Ordem):
    def test_ordem_da_especificacao(self):
        self.crescente(ov.semver_key, ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                                       "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1",
                                       "1.1.0", "1.10.0", "2.0.0"])

    def test_build_e_prefixo_v_nao_mudam_a_ordem(self):
        self.iguais(ov.semver_key, "1.2.3", "v1.2.3", "1.2.3+build.5")

    def test_pseudo_versao_do_go(self):
        self.crescente(ov.semver_key, ["0.0.0-20200101000000-abcdefabcdef", "0.0.0-20210101000000-abcdefabcdef",
                                       "0.1.0"])

    def test_invalida(self):
        with self.assertRaises(ov.VersaoInvalida):
            ov.semver_key("banana")


class TestPep440(Ordem):
    def test_ordem_da_pep(self):
        self.crescente(ov.pep440_key, [
            "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
            "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5",
            "1.0+abc.7", "1.0+5", "1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1"])

    def test_normalizacao(self):
        self.iguais(ov.pep440_key, "1.0", "1.0.0", "1.0.0.0", "v1.0")
        self.iguais(ov.pep440_key, "1.0rc1", "1.0.RC1", "1.0-rc-1", "1.0c1", "1.0pre1")
        self.iguais(ov.pep440_key, "1.0.post1", "1.0-1", "1.0.r1", "1.0post1")
        self.iguais(ov.pep440_key, "1.0a1", "1.0alpha1", "1.0.a.1")

    def test_epoca(self):
        self.assertGreater(ov.pep440_key("1!0.1"), ov.pep440_key("2024.1"))

    def test_invalida(self):
        with self.assertRaises(ov.VersaoInvalida):
            ov.pep440_key("1.0-banana")


class TestMaven(Ordem):
    def test_qualificadores(self):
        self.crescente(ov.maven_key, [
            "1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11",
            "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def",
            "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123"])

    def test_numeros(self):
        self.crescente(ov.maven_key, [
            # "2-1" antes de "2.0.a": na especificação de ordem do Maven, "-número" < ".número"
            "2.0", "2-1", "2.0.a", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
            "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11",
            "11.a", "11b", "11c", "11m"])

    def test_equivalencias(self):
        self.iguais(ov.maven_key, "1", "1.0", "1.0.0", "1-0", "1.0-0", "1.ga", "1-final", "1.RELEASE")
        self.iguais(ov.maven_key, "1a1", "1-alpha-1", "1alpha1")
        self.iguais(ov.maven_key, "1cr", "1rc")
        self.iguais(ov.maven_key, "1X", "1x")

    def test_casos_reais_de_aviso(self):
        self.crescente(ov.maven_key, ["2.13.4", "2.13.4.1", "2.13.4.2", "2.13.5", "2.14.0-rc1", "2.14.0"])
        self.crescente(ov.maven_key, ["5.3.17", "5.3.18", "6.0.0-M1", "6.0.0-RC1", "6.0.0"])


class TestRubyGems(Ordem):
    def test_ordem(self):
        self.crescente(ov.gem_key, ["1.0.a", "1.0.b1", "1.0.b2", "1.0.rc1", "1.0", "1.0.1", "1.1", "1.10"])

    def test_equivalencias(self):
        self.iguais(ov.gem_key, "1.0", "1.0.0", "1")
        self.assertLess(ov.gem_key("1.0.0-beta"), ov.gem_key("1.0.0"))


class TestNuget(Ordem):
    def test_ordem(self):
        self.crescente(ov.nuget_key, ["1.0.0-alpha", "1.0.0-beta", "1.0.0-beta.2", "1.0.0", "1.0.0.1", "1.0.1"])

    def test_equivalencias(self):
        self.iguais(ov.nuget_key, "1.0", "1.0.0", "1.0.0.0")
        self.iguais(ov.nuget_key, "1.0.0-ALPHA", "1.0.0-alpha")


class TestComposer(Ordem):
    def test_ordem(self):
        self.crescente(ov.composer_key, ["1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0",
                                         "1.0.0-p1", "1.0.1", "1.0.10"])

    def test_prefixo_v(self):
        self.iguais(ov.composer_key, "v5.4.0", "5.4.0")


def faixa(tipo, *eventos):
    return {"type": tipo, "events": [dict([e]) for e in eventos]}


class TestAvaliacaoDeFaixa(unittest.TestCase):
    def test_introduzida_e_corrigida(self):
        afetado = {"ranges": [faixa("SEMVER", ("introduced", "0"), ("fixed", "4.17.21"))]}
        self.assertTrue(ov.is_affected("npm", "4.17.20", afetado))
        self.assertFalse(ov.is_affected("npm", "4.17.21", afetado))
        self.assertTrue(ov.is_affected("npm", "4.17.21-beta.1", afetado))

    def test_varios_intervalos(self):
        afetado = {"ranges": [faixa("SEMVER", ("introduced", "2.0.0"), ("fixed", "2.5.0"),
                                    ("introduced", "1.0.0"), ("fixed", "1.5.0"))]}
        self.assertFalse(ov.is_affected("npm", "0.9.0", afetado))
        self.assertTrue(ov.is_affected("npm", "1.2.0", afetado))
        self.assertFalse(ov.is_affected("npm", "1.7.0", afetado))
        self.assertTrue(ov.is_affected("npm", "2.2.0", afetado))
        self.assertFalse(ov.is_affected("npm", "3.0.0", afetado))

    def test_ultima_afetada(self):
        afetado = {"ranges": [faixa("ECOSYSTEM", ("introduced", "1.0"), ("last_affected", "1.3"))]}
        self.assertTrue(ov.is_affected("PyPI", "1.3", afetado))
        self.assertTrue(ov.is_affected("PyPI", "1.3.0", afetado))
        self.assertFalse(ov.is_affected("PyPI", "1.3.1", afetado))

    def test_pre_lancamento_no_pypi(self):
        afetado = {"ranges": [faixa("ECOSYSTEM", ("introduced", "0"), ("fixed", "2.0rc1"))]}
        self.assertTrue(ov.is_affected("PyPI", "2.0b1", afetado))
        self.assertFalse(ov.is_affected("PyPI", "2.0", afetado))

    def test_lista_de_versoes_com_normalizacao(self):
        afetado = {"versions": ["1.0", "1.1"]}
        self.assertTrue(ov.is_affected("PyPI", "1.0.0", afetado))
        self.assertFalse(ov.is_affected("PyPI", "1.2", afetado))

    def test_pacote_malicioso_sem_faixa(self):
        self.assertTrue(ov.is_affected("npm", "9.9.9", {"package": {"name": "x"}}))

    def test_nao_avaliavel_nunca_vira_seguro(self):
        afetado = {"ranges": [faixa("SEMVER", ("introduced", "0"), ("fixed", "1.0.0"))]}
        self.assertIsNone(ov.is_affected("npm", "banana", afetado))
        self.assertIsNone(ov.is_affected("npm", "1.0.0", {"ranges": [faixa("GIT", ("introduced", "abc"))]}))
        self.assertIsNone(ov.is_affected("Hex", "1.0.0", {"ranges": [faixa("ECOSYSTEM", ("introduced", "0"))]}))
        misto = {"ranges": [faixa("SEMVER", ("introduced", "5.0.0")),
                            faixa("ECOSYSTEM", ("introduced", "0"), ("fixed", "x!y"))]}
        self.assertIsNone(ov.is_affected("npm", "1.0.0", misto))


if __name__ == "__main__":
    unittest.main(verbosity=2)
