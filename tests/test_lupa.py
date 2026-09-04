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


class LeadEnrichmentTests(unittest.TestCase):
    def test_receitaws_is_normalized_only_for_exact_cnpj(self):
        payload = {
            "status": "OK",
            "cnpj": "11.222.333/0001-81",
            "nome": "ACME LTDA",
            "fantasia": "ACME",
            "capital_social": "218878.00",
            "email": "vendas@acme.test",
            "telefone": "(11) 3333-4444 / (11) 99999-8888",
            "atividade_principal": [{"code": "62.01-5-01", "text": "Software"}],
            "atividades_secundarias": [],
            "qsa": [],
        }
        record = lupa.normalize_cnpj_api("ReceitaWS", payload, "11222333000181")
        self.assertIsNotNone(record)
        self.assertEqual(record["capital_social"], 218878.0)
        self.assertEqual(record["ddd_telefone_1"], "551133334444")
        self.assertEqual(record["ddd_telefone_2"], "5511999998888")
        self.assertEqual(record["cnae_fiscal"], "6201501")
        self.assertIsNone(lupa.normalize_cnpj_api("ReceitaWS", payload, "11222333000180"))

    def test_business_page_extracts_structured_and_explicit_contacts(self):
        html = """
        <html><head>
          <script type="application/ld+json">
          {"@type":"Organization","contactPoint":{"@type":"ContactPoint",
           "contactType":"sales","telephone":"+55 11 3333-4444","email":"vendas@acme.test"}}
          </script>
        </head><body>
          <a href="tel:+5511999998888">WhatsApp comercial</a>
          <a href="mailto:contato@acme.test">Contato</a>
          <a href="/fale-conosco">Fale conosco</a>
        </body></html>
        """
        contacts, links, _ = lupa.extract_business_contacts_from_html(html, "https://acme.test/")
        values = {(item["channel"], item["value"]) for item in contacts}
        self.assertIn(("phone", "+551133334444"), values)
        self.assertIn(("phone", "+5511999998888"), values)
        self.assertIn(("email", "vendas@acme.test"), values)
        self.assertIn("https://acme.test/fale-conosco", links)

    def test_rdap_validates_company_but_suppresses_registry_contacts_from_sales(self):
        payload = {
            "ldhName": "acme.com.br",
            "handle": "acme.com.br",
            "entities": [{
                "handle": "11222333000181",
                "roles": ["registrant"],
                "publicIds": [{"type": "cnpj", "identifier": "11.222.333/0001-81"}],
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["kind", {}, "text", "org"],
                    ["fn", {}, "text", "ACME LTDA"],
                    ["tel", {}, "uri", "tel:+551133334444"],
                    ["email", {}, "text", "registro@acme.test"],
                ]],
            }],
        }
        with mock.patch.object(lupa, "http_json", return_value=(payload, None)):
            result = lupa.query_domain_rdap("acme.com.br", "11222333000181", 1)
        self.assertEqual(result["status"], "match")
        record = result["records"][0]
        self.assertTrue(record["registrant_cnpj_exact"])
        entity = record["entities"][0]
        self.assertEqual(entity["published_contact_fields"], ["email", "tel"])
        self.assertFalse(entity["contact_values_exported"])
        self.assertNotIn("registro@acme.test", json.dumps(result))
        self.assertNotIn("+551133334444", json.dumps(result))
        with mock.patch.object(lupa, "http_json", return_value=(payload, None)):
            verification_result = lupa.query_domain_rdap(
                "acme.com.br", "11222333000181", 1, include_contact_values=True
            )
        verification_contacts = verification_result["records"][0]["entities"][0]["verification_contacts"]
        self.assertEqual({item["value"] for item in verification_contacts}, {
            "registro@acme.test", "+551133334444",
        })
        self.assertTrue(all(not item["sales_eligible"] for item in verification_contacts))

    def test_registrobr_whois_contacts_are_verification_only(self):
        response = """
        domain:      acme.com.br
        owner:       ACME LTDA
        ownerid:     11.222.333/0001-81
        owner-c:     ACME1
        tech-c:      TECH1

        nic-hdl-br:  ACME1
        person:      Contato ACME
        e-mail:      registro@acme.test
        phone:       +55 11 3333-4444

        nic-hdl-br:  TECH1
        person:      Suporte ACME
        e-mail:      suporte@acme.test
        """
        parsed = lupa.parse_registrobr_whois(response, "acme.com.br", "11222333000181")
        self.assertTrue(parsed["domain_exact"])
        self.assertTrue(parsed["owner_cnpj_exact"])
        self.assertEqual({item["value"] for item in parsed["verification_contacts"]}, {
            "registro@acme.test", "+551133334444", "suporte@acme.test",
        })
        self.assertTrue(all(item["verification_only"] for item in parsed["verification_contacts"]))
        self.assertTrue(all(not item["sales_eligible"] for item in parsed["verification_contacts"]))

    def test_cvm_connector_keeps_company_and_responsible_phones(self):
        header = (
            "CNPJ_CIA;DENOM_SOCIAL;DDD_TEL;TEL;EMAIL;TP_RESP;RESP;"
            "DDD_TEL_RESP;TEL_RESP;EMAIL_RESP\n"
        )
        row = (
            "11.222.333/0001-81;ACME S.A.;11;33334444;ri@acme.test;"
            "DIRETOR DE RI;PESSOA;11;999998888;diretoria.ri@acme.test\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cvm" / "cad_cia_aberta.csv"
            path.parent.mkdir()
            path.write_text(header + row, encoding="latin-1")
            result = lupa.query_cvm_cnpj("11222333000181", Path(directory), 1, False)
        self.assertEqual(result["status"], "match")
        record = result["records"][0]
        self.assertEqual(record["DDD_TEL"], "11")
        self.assertEqual(record["TEL"], "33334444")
        self.assertEqual(record["DDD_TEL_RESP"], "11")
        self.assertEqual(record["TEL_RESP"], "999998888")

    def test_seller_profile_excludes_personal_email_and_isolated_mobile(self):
        data = {
            "cnpj": "11222333000181",
            "razao_social": "ACME LTDA",
            "email": "pessoa@gmail.com",
        }
        results = [
            lupa.result_base(
                "cnpj_api_brasilapi", "BrasilAPI", "https://example.test", "match",
                records=[{
                    "email": "pessoa@gmail.com",
                    "ddd_telefone_1": "11999998888",
                    "ddd_telefone_2": "",
                }],
            ),
            lupa.result_base(
                "whois_registrobr_fixture", "WHOIS Registro.br", "https://registro.br/", "match",
                records=[{"verification_contacts": [{
                    "channel": "phone", "value": "+551132222222",
                    "verification_only": True, "sales_eligible": False,
                }]}],
            ),
        ]
        websites = [{
            "status": "verified",
            "contacts": [{
                "channel": "email",
                "value": "vendas@acme.test",
                "contact_role": "sales",
                "source_id": "official_website_fixture",
                "source_name": "Site ACME",
                "source_url": "https://acme.test/contato",
                "queried_at": "2026-01-01T00:00:00+00:00",
                "match_method": "exact_cnpj_on_homepage",
                "extraction_method": "json_ld",
            }],
        }]
        profile = lupa.build_lead_profile(data, results, websites, [])
        ready_values = {item["value"] for item in profile["seller_ready_contacts"]}
        self.assertIn("vendas@acme.test", ready_values)
        self.assertNotIn("pessoa@gmail.com", ready_values)
        self.assertNotIn("+5511999998888", ready_values)
        self.assertNotIn("+551132222222", ready_values)


if __name__ == "__main__":
    unittest.main()
