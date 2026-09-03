import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile


LUPA_PATH = Path(__file__).parents[1] / "lupa.py"
loader = importlib.machinery.SourceFileLoader("lupa_v7", str(LUPA_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
lupa = importlib.util.module_from_spec(spec)
loader.exec_module(lupa)


def cpf_fixture(base: str) -> str:
    """Gera um documento sintético com checksum apenas para testes offline."""
    numbers = [int(character) for character in base]
    first_sum = sum(numbers[index] * (10 - index) for index in range(9))
    first = 0 if first_sum % 11 < 2 else 11 - (first_sum % 11)
    numbers.append(first)
    second_sum = sum(numbers[index] * (11 - index) for index in range(10))
    second = 0 if second_sum % 11 < 2 else 11 - (second_sum % 11)
    return base + str(first) + str(second)


CPF_A = cpf_fixture("529982247")
CPF_B = cpf_fixture("000000001")


class DocumentValidationTests(unittest.TestCase):
    def test_cpf_checksum(self):
        self.assertTrue(lupa.validate_cpf(CPF_A))
        self.assertTrue(lupa.validate_cpf(CPF_B))
        self.assertFalse(lupa.validate_cpf("1" * 11))
        self.assertFalse(lupa.validate_cpf(CPF_A[:-1] + str((int(CPF_A[-1]) + 1) % 10)))

    def test_cnpj_checksum(self):
        self.assertTrue(lupa.validate_cnpj("11.222.333/0001-81"))
        self.assertFalse(lupa.validate_cnpj("00.000.000/0000-00"))
        self.assertFalse(lupa.validate_cnpj("11.222.333/0001-80"))

    def test_sanitizer_masks_embedded_cpf(self):
        cpf = CPF_A
        value = {
            "plain": cpf,
            "formatted": lupa.format_cpf(cpf),
            "sentence": f"documento {cpf} confirmado",
        }
        serialized = json.dumps(lupa.sanitize_cpf_value(value, cpf))
        self.assertNotIn(cpf, serialized)
        self.assertNotIn(lupa.format_cpf(cpf), serialized)


class ExactMatchingTests(unittest.TestCase):
    def test_masked_cgu_source_requires_free_official_key(self):
        with mock.patch.dict(os.environ, {"LUPA_TRANSPARENCIA_API_KEY": ""}):
            result = lupa.query_cgu(
                "cgu_pep", CPF_A, Path("/tmp/unused-lupa-cache"), 1, False
            )
        self.assertEqual(result["status"], "not_configured")
        self.assertIn("mascara", result["details"]["reason"])

    def test_tcu_discards_non_exact_document(self):
        cpf = CPF_A
        rows = [
            {"numeroRegistro": lupa.format_cpf(CPF_B), "nome": "HOMONIMO"},
            {"numeroRegistro": lupa.format_cpf(CPF_A), "nome": "NOME EXATO"},
        ]
        with mock.patch.object(lupa, "http_json", return_value=(rows, None)):
            result = lupa.query_tcu("tcu_inabilitados", cpf, 1)
        self.assertEqual(result["status"], "match")
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["nome"], "NOME EXATO")
        self.assertEqual(result["details"]["discarded_non_exact"], 1)
        self.assertNotIn(cpf, json.dumps(result))

    def test_csv_zip_uses_exact_document_not_name(self):
        cpf = CPF_A
        content = (
            '"CPF OU CNPJ DO SANCIONADO";"NOME DO SANCIONADO";"NÚMERO DO PROCESSO"\n'
            f'"{CPF_B}";"MESMO NOME";"A"\n'
            f'"{CPF_A}";"MESMO NOME";"B"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("fixture.csv", content.encode("latin-1"))
            records, details, error = lupa.scan_zip_csv_exact(
                path,
                cpf,
                ["CPF OU CNPJ DO SANCIONADO"],
                ["NOME DO SANCIONADO", "NÚMERO DO PROCESSO"],
            )
        self.assertIsNone(error)
        self.assertEqual(details["rows_scanned"], 2)
        self.assertEqual(records, [{"NOME DO SANCIONADO": "MESMO NOME", "NÚMERO DO PROCESSO": "B"}])

    def test_compras_discards_non_exact_document(self):
        payload = {
            "resultado": [
                {"cnpj": "11222333000180", "nomeRazaoSocialFornecedor": "DIVERGENTE"},
                {"cnpj": "11222333000181", "nomeRazaoSocialFornecedor": "EXATO"},
            ],
            "totalPaginas": 1,
        }
        with mock.patch.object(lupa, "http_json", return_value=(payload, None)):
            result = lupa.query_compras_supplier("11222333000181", "cnpj", 1)
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["records"][0]["nomeRazaoSocialFornecedor"], "EXATO")
        self.assertEqual(result["details"]["discarded_non_exact"], 1)

    def test_cnpj_consensus_keeps_divergence_and_all_sources(self):
        records = [
            ("BrasilAPI", {"cnpj": "11222333000181", "razao_social": "ACME", "uf": "SP"}),
            ("MinhaReceita", {"cnpj": "11222333000181", "razao_social": "ACME", "uf": "SP"}),
            ("CNPJ.ws", {"cnpj": "11222333000181", "razao_social": "ACME SA", "uf": "RJ"}),
        ]
        merged = lupa.aggregate_cnpj_records(records, "11222333000181")
        self.assertEqual(merged["razao_social"], "ACME")
        self.assertEqual(merged["uf"], "SP")
        self.assertIn("razao_social", merged["_lupa_consensus"]["divergences"])
        self.assertEqual(len(merged["_lupa_source_records"]), 3)

    def test_bcb_root_match_is_explicitly_not_full_document_match(self):
        payload = {"value": [{"codigoCNPJ8": "11222333", "codigoCNPJ14": "11222333999900"}]}
        with mock.patch.object(lupa, "http_json", return_value=(payload, None)):
            result = lupa.query_bcb_cnpj("11222333000181", 1)
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["match_method"], "cnpj_root_exact")
        self.assertLess(result["confidence"], 1.0)


class LocalIndexTests(unittest.TestCase):
    def test_rfb_index_joins_exact_establishment_company_and_partners(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            cache = Path(directory) / "cache"
            source.mkdir()
            fixtures = {
                "K.EMPRESAS.zip": "11222333;ACME LTDA;2062;49;1000,00;01;\n",
                "K.ESTABELECIMENTOS.zip": (
                    "11222333;0001;81;1;ACME;02;20200101;00;;;20200101;6201501;;RUA;A;1;;CENTRO;"
                    "01001000;SP;7107;11;12345678;;;;;a@acme.test;;\n"
                ),
                "K.SOCIOS.zip": "11222333;2;SOCIO EXATO;***123**;49;20200101;;;;;5\n",
                "K.SIMPLES.zip": "11222333;S;20200101;;N;;\n",
            }
            for filename, content in fixtures.items():
                path = source / filename
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(filename.replace(".zip", ".csv"), content.encode("latin-1"))
            self.assertEqual(lupa.build_rfb_index(source, cache), 0)
            result = lupa.query_rfb_index("11222333000181", cache)
            self.assertEqual(result["status"], "match")
            bundle = result["records"][0]
            self.assertEqual(bundle["empresa"]["razao_social"], "ACME LTDA")
            self.assertEqual(bundle["socios"][0]["nome_socio"], "SOCIO EXATO")

    def test_history_key_never_contains_raw_cpf(self):
        cpf = CPF_A
        report = {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "target": {"type": "CPF", "masked_document": lupa.mask_cpf(cpf)},
            "sources": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            lupa.save_history(report, cpf, cache)
            paths = [str(path) for path in cache.rglob("*")]
            self.assertFalse(any(cpf in path for path in paths))
            serialized = "".join(
                path.read_text(encoding="utf-8")
                for path in cache.rglob("*.json")
            )
            self.assertNotIn(cpf, serialized)

    def test_pncp_index_masks_every_cpf_and_queries_by_hmac(self):
        cpf_primary = CPF_A
        cpf_sub = CPF_B
        payload = {
            "data": [{
                "numeroControlePNCP": "fixture-1",
                "niFornecedor": cpf_primary,
                "niFornecedorSubContratado": cpf_sub,
                "nomeRazaoSocialFornecedor": "FORNECEDOR TESTE",
            }],
            "totalPaginas": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with mock.patch.object(lupa, "http_json", return_value=(payload, None)):
                self.assertEqual(lupa.sync_pncp(1, cache, 1), 0)
            database = (cache / "pncp.sqlite").read_bytes()
            self.assertNotIn(cpf_primary.encode(), database)
            self.assertNotIn(cpf_sub.encode(), database)
            result = lupa.query_pncp_index(cpf_primary, cache)
            self.assertEqual(result["status"], "match")
            serialized = json.dumps(result)
            self.assertNotIn(cpf_primary, serialized)
            self.assertNotIn(cpf_sub, serialized)


if __name__ == "__main__":
    unittest.main()
