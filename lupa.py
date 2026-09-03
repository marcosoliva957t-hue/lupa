#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LUPA v7.0 - OSINT passivo por CNPJ e CPF (Kali Edition)

Princípios do modo CPF:
- somente fontes públicas/abertas e gratuitas;
- correspondência por documento exato, nunca apenas por nome;
- nenhum CAPTCHA, login, bloqueio ou limitação é contornado;
- o CPF bruto não é impresso nem persistido nos relatórios;
- cada achado inclui fonte, URL, data da consulta e tipo de correspondência.

O modo CNPJ mantém as capacidades da LUPA 5.1, mas remove inferências que
produziam falsos positivos (associação por nome, GitHub pelo primeiro termo,
domínios inferidos de handles RDAP e metadados de documento de demonstração).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile


VERSION = "7.0.0"
SCHEMA_VERSION = "lupa.report.v2"
USER_AGENT = f"LUPA/{VERSION} (+OSINT passivo; fontes publicas)"
MAX_JSON_BYTES = 12 * 1024 * 1024
MAX_DATASET_BYTES = 250 * 1024 * 1024
MAX_RFB_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
PNCP_API = "https://pncp.gov.br/api/consulta/v1/contratos"
COMPRAS_API = "https://dadosabertos.compras.gov.br/modulo-fornecedor/1_consultarFornecedor"
CVM_DATASET = "https://dados.cvm.gov.br/dados/CIA_ABERTA/CAD/DADOS/cad_cia_aberta.csv"
BCB_ODATA = "https://olinda.bcb.gov.br/olinda/servico/BcBase/versao/v2/odata"
TCU_CNPJ_API = "https://certidoes-apf.apps.tcu.gov.br/api/rest/publico/certidoes"
_LOCAL_SECRET_CACHE: dict[str, bytes] = {}

G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
C = "\033[96m"
M = "\033[95m"
W = "\033[0m"
B = "\033[1m"


def disable_colors() -> None:
    global G, Y, R, C, M, W, B
    G = Y = R = C = M = W = B = ""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def only_digits(value: object) -> str:
    return re.sub(r"\D", "", str(value or ""))


def normalize_text(value: object) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def normalize_header(value: object) -> str:
    return normalize_text(value).replace(" ", "")


def validate_cpf(cpf: str) -> bool:
    cpf = only_digits(cpf)
    if len(cpf) != 11 or len(set(cpf)) == 1:
        return False
    numbers = [int(ch) for ch in cpf]
    first_sum = sum(numbers[i] * (10 - i) for i in range(9))
    first = 0 if first_sum % 11 < 2 else 11 - (first_sum % 11)
    second_sum = sum(numbers[i] * (11 - i) for i in range(10))
    second = 0 if second_sum % 11 < 2 else 11 - (second_sum % 11)
    return numbers[9] == first and numbers[10] == second


def validate_cnpj(cnpj: str) -> bool:
    cnpj = only_digits(cnpj)
    if len(cnpj) != 14 or len(set(cnpj)) == 1:
        return False
    numbers = [int(ch) for ch in cnpj]
    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total_1 = sum(n * w for n, w in zip(numbers[:12], weights_1))
    first = 0 if total_1 % 11 < 2 else 11 - (total_1 % 11)
    total_2 = sum(n * w for n, w in zip(numbers[:13], weights_2))
    second = 0 if total_2 % 11 < 2 else 11 - (total_2 % 11)
    return numbers[12] == first and numbers[13] == second


def format_cpf(cpf: str) -> str:
    cpf = only_digits(cpf)
    return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"


def mask_cpf(cpf: str) -> str:
    cpf = only_digits(cpf)
    return f"***.***.***-{cpf[-2:]}"


def format_cnpj(cnpj: str) -> str:
    cnpj = only_digits(cnpj)
    return f"{cnpj[:2]}.{cnpj[2:5]}.{cnpj[5:8]}/{cnpj[8:12]}-{cnpj[12:]}"


def banner(mode: str) -> None:
    print(f"{C}{B}")
    print("  ██╗     ██╗██╗  ██╗██████╗  █████╗ ")
    print("  ██║     ██║██║  ██║██╔══██╗██╔══██╗")
    print("  ██║     ██║██║  ██║██████╔╝███████║")
    print("  ██║     ██║██║  ██║██╔═══╝ ██╔══██║")
    print("  ███████╗╚███████╔╝██║     ██║  ██║")
    print(f"  ╚══════╝ ╚══════╝ ╚═╝     ╚═╝  ╚═╝ {W}{Y}v{VERSION}{W}")
    print(f"{C}  [ LUPA - OSINT passivo por CNPJ e CPF | modo {mode.upper()} ]{W}")
    print(f"{G}  [✓] Fontes abertas | evidência rastreável | vínculo exato{W}\n")


def run_cmd(cmd: list[str], timeout: int = 15) -> str | None:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def http_bytes(
    url: str,
    *,
    timeout: float = 15,
    method: str = "GET",
    payload: dict | None = None,
    accept: str = "application/json",
    max_bytes: int = MAX_JSON_BYTES,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bytes | None, str | None]:
    body = None
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if extra_headers:
        headers.update(extra_headers)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                return None, f"resposta excede o limite de {max_bytes} bytes"
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                return None, f"resposta excede o limite de {max_bytes} bytes"
            return data, None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return None, f"falha de rede: {reason}"
    except (OSError, ValueError) as exc:
        return None, f"falha de leitura: {exc}"


def http_json(
    url: str,
    *,
    timeout: float = 15,
    method: str = "GET",
    payload: dict | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[object | None, str | None]:
    raw, error = http_bytes(
        url, timeout=timeout, method=method, payload=payload, extra_headers=extra_headers
    )
    if error:
        return None, error
    try:
        return json.loads((raw or b"").decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"JSON inválido: {exc}"


def make_http_request(url: str, timeout: float = 10) -> object | None:
    data, _ = http_json(url, timeout=timeout)
    return data


def result_base(
    source_id: str,
    source_name: str,
    source_url: str,
    status: str,
    *,
    records: list[dict] | None = None,
    error: str | None = None,
    details: dict | None = None,
    latency_ms: int | None = None,
) -> dict:
    result = {
        "source_id": source_id,
        "source_name": source_name,
        "source_url": source_url,
        "queried_at": utc_now(),
        "status": status,
        "match_method": "document_exact" if status == "match" else None,
        "confidence": 1.0 if status == "match" else None,
        "records": records or [],
    }
    if error:
        result["error"] = error
    if details:
        result["details"] = details
    if latency_ms is not None:
        result["latency_ms"] = latency_ms
    return result


def timed_call(callable_job: object) -> dict:
    """Executa um conector isoladamente e anexa latência observada."""
    started = time.monotonic()
    result = callable_job()  # type: ignore[operator]
    if isinstance(result, dict):
        result["latency_ms"] = round((time.monotonic() - started) * 1000)
    return result


def deduplicate_records(results: list[dict]) -> list[dict]:
    """Remove apenas registros byte-a-byte equivalentes dentro da mesma fonte."""
    for result in results:
        seen: set[str] = set()
        unique: list[dict] = []
        duplicates = 0
        for record in result.get("records", []):
            key = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            unique.append(record)
        result["records"] = unique
        if duplicates:
            result.setdefault("details", {})["duplicates_removed"] = duplicates
    return results


def source_status_summary(results: list[dict]) -> dict:
    summary: dict[str, int] = {}
    for result in results:
        status = str(result.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary


def download_plain_file(
    url: str,
    destination: Path,
    timeout: float,
    *,
    max_bytes: int = MAX_DATASET_BYTES,
) -> tuple[Path | None, str | None]:
    """Baixa arquivo oficial de forma atômica, sem aceitar conteúdo ilimitado."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                return None, f"arquivo excede o limite de {max_bytes} bytes"
            total = 0
            with temporary.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"arquivo excede o limite de {max_bytes} bytes")
                    output.write(chunk)
        os.replace(temporary, destination)
        return destination, None
    except urllib.error.HTTPError as exc:
        temporary.unlink(missing_ok=True)
        return None, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        temporary.unlink(missing_ok=True)
        return None, f"falha de rede: {getattr(exc, 'reason', exc)}"
    except (OSError, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        return None, str(exc)


def sanitize_cpf_value(value: object, cpf: str) -> object:
    if isinstance(value, dict):
        return {str(k): sanitize_cpf_value(v, cpf) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_cpf_value(v, cpf) for v in value]
    if isinstance(value, tuple):
        return [sanitize_cpf_value(v, cpf) for v in value]
    if isinstance(value, str):
        return value.replace(format_cpf(cpf), mask_cpf(cpf)).replace(cpf, mask_cpf(cpf))
    return value


TCU_SOURCES = {
    "tcu_inabilitados": {
        "name": "TCU - Responsáveis inabilitados",
        "endpoint": "responsaveis-inabilitados",
    },
    "tcu_inidoneos": {
        "name": "TCU - Licitantes inidôneos",
        "endpoint": "responsaveis-inidoneos",
    },
    "tcu_contas_irregulares": {
        "name": "TCU - Contas julgadas irregulares (CADIRREG)",
        "endpoint": "responsaveis-contas-irregulares",
    },
    "tcu_fins_eleitorais": {
        "name": "TCU - Contas irregulares com possível implicação eleitoral",
        "endpoint": "responsaveis-fins-eleitorais",
    },
}

TCU_ALLOWED_FIELDS = {
    "numeroProcessoFormatado",
    "nome",
    "tipoRegistro",
    "numeroRegistro",
    "municipio",
    "uf",
    "numeroAcordaoFormatado",
    "dataAcordao",
    "dataTransitoEmJulgado",
    "dataFinalSancao",
    "dataFinalFinsEleitorais",
    "linkDeliberacoesProcesso",
    "linkAcompanhamentoProcesso",
}


def query_tcu(source_id: str, cpf: str, timeout: float) -> dict:
    config = TCU_SOURCES[source_id]
    url = f"https://certidoes.apps.tcu.gov.br/api/publico/{config['endpoint']}"
    data, error = http_json(
        url,
        timeout=timeout,
        method="POST",
        payload={"cpf": format_cpf(cpf)},
    )
    if error:
        return result_base(source_id, config["name"], url, "error", error=error)
    if not isinstance(data, list):
        return result_base(
            source_id,
            config["name"],
            url,
            "error",
            error="formato de resposta inesperado",
        )

    verified: list[dict] = []
    discarded = 0
    for row in data:
        if not isinstance(row, dict):
            discarded += 1
            continue
        returned = only_digits(row.get("numeroRegistro") or row.get("cpf"))
        if returned != cpf:
            discarded += 1
            continue
        selected = {k: row.get(k) for k in TCU_ALLOWED_FIELDS if k in row}
        verified.append(sanitize_cpf_value(selected, cpf))

    status = "match" if verified else "no_match"
    return result_base(
        source_id,
        config["name"],
        url,
        status,
        records=verified,
        details={"discarded_non_exact": discarded},
    )


def query_tcu_cnpj(cnpj: str, timeout: float) -> dict:
    """Consulta consolidada oficial do TCU por CNPJ exato."""
    public_url = "https://certidoes-apf.apps.tcu.gov.br/"
    url = f"{TCU_CNPJ_API}/{cnpj}?seEmitirPDF=false"
    data, error = http_json(url, timeout=timeout)
    if error:
        return result_base("tcu_certidoes_cnpj", "TCU - certidões APF", public_url, "error", error=error)
    if not isinstance(data, dict):
        return result_base(
            "tcu_certidoes_cnpj", "TCU - certidões APF", public_url, "error",
            error="formato de resposta inesperado",
        )
    returned = only_digits(data.get("cnpj"))
    if returned != cnpj:
        return result_base(
            "tcu_certidoes_cnpj", "TCU - certidões APF", public_url, "no_match",
            details={"discarded_non_exact": 1},
        )
    record = {
        key: data.get(key)
        for key in ("cnpj", "razaoSocial", "nomeFantasia", "certidoes")
        if key in data
    }
    return result_base(
        "tcu_certidoes_cnpj", "TCU - certidões APF", public_url, "match", records=[record]
    )


def query_compras_supplier(document: str, document_type: str, timeout: float) -> dict:
    """Consulta fornecedor do Compras.gov.br e valida o documento devolvido."""
    parameter = "cpf" if document_type == "cpf" else "cnpj"
    query = urllib.parse.urlencode(
        {"pagina": 1, "tamanhoPagina": 100, parameter: document, "ativo": "true"}
    )
    data, error = http_json(f"{COMPRAS_API}?{query}", timeout=timeout)
    name = "Compras.gov.br - fornecedores"
    if error:
        return result_base("compras_fornecedor", name, COMPRAS_API, "error", error=error)
    if not isinstance(data, dict):
        return result_base(
            "compras_fornecedor", name, COMPRAS_API, "error",
            error="formato de resposta inesperado",
        )
    rows = data.get("resultado") or data.get("data") or []
    if not isinstance(rows, list):
        rows = []
    verified: list[dict] = []
    discarded = 0
    allowed = {
        "cnpj", "cpf", "habilitadoLicitar", "codigoCnae", "nomeCnae",
        "nomeMunicipio", "ufSigla", "naturezaJuridicaId", "naturezaJuridicaNome",
        "porteEmpresaId", "porteEmpresaNome", "nomeRazaoSocialFornecedor",
    }
    for row in rows:
        if not isinstance(row, dict):
            discarded += 1
            continue
        returned = only_digits(row.get(parameter))
        if returned != document:
            discarded += 1
            continue
        verified.append({key: row.get(key) for key in allowed if key in row})
    records: list[dict] = verified
    if document_type == "cpf":
        records = sanitize_cpf_value(records, document)  # type: ignore[assignment]
    return result_base(
        "compras_fornecedor", name, COMPRAS_API,
        "match" if records else "no_match", records=records,
        details={
            "discarded_non_exact": discarded,
            "total_pages": data.get("totalPaginas"),
            "scope": "fornecedores ativos cadastrados no Compras.gov.br",
        },
    )


CGU_SOURCES = {
    "cgu_cepim": {
        "slug": "cepim",
        "name": "CGU - CEPIM",
        "document_types": ["cnpj"],
        "exact_document_available": True,
        "document_headers": ["CNPJ ENTIDADE"],
        "allowed_headers": [
            "CNPJ ENTIDADE", "NOME ENTIDADE", "NÚMERO CONVÊNIO",
            "ÓRGÃO CONCEDENTE", "MOTIVO DO IMPEDIMENTO",
        ],
    },
    "cgu_ceis": {
        "slug": "ceis",
        "name": "CGU - CEIS",
        "document_types": ["cpf", "cnpj"],
        "exact_document_available": True,
        "document_headers": ["CPF OU CNPJ DO SANCIONADO"],
        "allowed_headers": [
            "CADASTRO", "CÓDIGO DA SANÇÃO", "TIPO DE PESSOA", "NOME DO SANCIONADO",
            "NOME INFORMADO PELO ÓRGÃO SANCIONADOR", "NÚMERO DO PROCESSO",
            "CATEGORIA DA SANÇÃO", "DATA INÍCIO SANÇÃO", "DATA FINAL SANÇÃO",
            "DATA PUBLICAÇÃO", "PUBLICAÇÃO", "DETALHAMENTO DO MEIO DE PUBLICAÇÃO",
            "DATA DO TRÂNSITO EM JULGADO", "ABRAGÊNCIA DA SANÇÃO", "ÓRGÃO SANCIONADOR",
            "UF ÓRGÃO SANCIONADOR", "ESFERA ÓRGÃO SANCIONADOR", "FUNDAMENTAÇÃO LEGAL",
            "DATA ORIGEM INFORMAÇÃO", "ORIGEM INFORMAÇÕES", "OBSERVAÇÕES",
        ],
    },
    "cgu_cnep": {
        "slug": "cnep",
        "name": "CGU - CNEP",
        "document_types": ["cpf", "cnpj"],
        "exact_document_available": True,
        "document_headers": ["CPF OU CNPJ DO SANCIONADO"],
        "allowed_headers": [
            "CADASTRO", "CÓDIGO DA SANÇÃO", "TIPO DE PESSOA", "NOME DO SANCIONADO",
            "NOME INFORMADO PELO ÓRGÃO SANCIONADOR", "NÚMERO DO PROCESSO",
            "CATEGORIA DA SANÇÃO", "VALOR DA MULTA", "DATA INÍCIO SANÇÃO",
            "DATA FINAL SANÇÃO", "DATA PUBLICAÇÃO", "PUBLICAÇÃO",
            "DATA DO TRÂNSITO EM JULGADO", "ABRAGÊNCIA DA SANÇÃO", "ÓRGÃO SANCIONADOR",
            "UF ÓRGÃO SANCIONADOR", "ESFERA ÓRGÃO SANCIONADOR", "FUNDAMENTAÇÃO LEGAL",
            "ORIGEM INFORMAÇÕES", "OBSERVAÇÕES",
        ],
    },
    "cgu_ceaf": {
        "slug": "ceaf",
        "name": "CGU - Expulsões da Administração Federal (CEAF)",
        "document_types": ["cpf"],
        "exact_document_available": False,
        "document_headers": ["CPF OU CNPJ DO SANCIONADO"],
        "allowed_headers": [
            "CADASTRO", "CÓDIGO DA SANÇÃO", "TIPO DE PESSOA", "NOME DO SANCIONADO",
            "CATEGORIA DA SANÇÃO", "NÚMERO DO DOCUMENTO", "NÚMERO DO PROCESSO",
            "DATA INÍCIO SANÇÃO", "DATA FINAL SANÇÃO", "DATA PUBLICAÇÃO", "PUBLICAÇÃO",
            "DATA DO TRÂNSITO EM JULGADO", "CARGO EFETIVO",
            "FUNÇÃO OU CARGO DE CONFIANÇA", "ÓRGÃO DE LOTAÇÃO", "ÓRGÃO SANCIONADOR",
            "UF ÓRGÃO SANCIONADOR", "ESFERA ÓRGÃO SANCIONADOR", "FUNDAMENTAÇÃO LEGAL",
            "ORIGEM INFORMAÇÕES", "OBSERVAÇÕES",
        ],
    },
    "cgu_pep": {
        "slug": "pep",
        "name": "CGU - Pessoas Expostas Politicamente (PEP)",
        "document_types": ["cpf"],
        "exact_document_available": False,
        "document_headers": ["CPF"],
        "allowed_headers": [
            "Nome_PEP", "Sigla_Função", "Descrição_Função", "Nível_Função",
            "Nome_Órgão", "Data_Início_Exercício", "Data_Fim_Exercício", "Data_Fim_Carência",
        ],
    },
}


def find_matching_header(headers: list[str], candidates: list[str]) -> str | None:
    by_normalized = {normalize_header(header): header for header in headers}
    for candidate in candidates:
        found = by_normalized.get(normalize_header(candidate))
        if found:
            return found
    return None


def latest_cgu_reference(slug: str, timeout: float) -> tuple[str | None, str | None]:
    page_url = f"https://portaldatransparencia.gov.br/download-de-dados/{slug}"
    raw, error = http_bytes(
        page_url,
        timeout=timeout,
        accept="text/html,application/xhtml+xml",
        max_bytes=4 * 1024 * 1024,
    )
    if error:
        return None, error
    text = (raw or b"").decode("utf-8", errors="replace")
    refs = re.findall(rf"/download-de-dados/{re.escape(slug)}/([0-9]{{6,8}})", text)
    # O Portal também publica as referências somente no JavaScript da página.
    for year, month, day in re.findall(
        r'"ano"\s*:\s*"(\d{4})"\s*,\s*"mes"\s*:\s*"(\d{2})"\s*,\s*"dia"\s*:\s*"(\d{2})"',
        text,
    ):
        refs.append(f"{year}{month}{day}")
    if not refs:
        return None, "referência mais recente não encontrada na página oficial"
    return max(refs), None


def download_dataset(url: str, destination: Path, timeout: float) -> tuple[Path | None, str | None]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/zip,application/octet-stream,*/*"},
    )
    temporary = destination.with_suffix(destination.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_DATASET_BYTES:
                return None, "dataset excede o limite de segurança"
            total = 0
            with temporary.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DATASET_BYTES:
                        raise ValueError("dataset excede o limite de segurança")
                    output.write(chunk)
        if not zipfile.is_zipfile(temporary):
            temporary.unlink(missing_ok=True)
            return None, "conteúdo recebido não é um ZIP válido"
        os.replace(temporary, destination)
        return destination, None
    except urllib.error.HTTPError as exc:
        temporary.unlink(missing_ok=True)
        return None, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        temporary.unlink(missing_ok=True)
        return None, f"falha de rede: {getattr(exc, 'reason', exc)}"
    except (OSError, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        return None, str(exc)


def select_csv_fields(row: dict[str, str], allowed_headers: list[str]) -> dict:
    by_normalized = {normalize_header(key): key for key in row}
    selected: dict[str, str] = {}
    for requested in allowed_headers:
        actual = by_normalized.get(normalize_header(requested))
        if actual is None:
            continue
        value = (row.get(actual) or "").strip()
        if value:
            selected[requested] = value
    return selected


def scan_zip_csv_exact(
    zip_path: Path,
    document: str,
    document_headers: list[str],
    allowed_headers: list[str],
    *,
    max_matches: int = 1000,
) -> tuple[list[dict], dict, str | None]:
    matches: list[dict] = []
    rows_scanned = 0
    files_scanned = 0
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = [name for name in archive.namelist() if name.lower().endswith((".csv", ".txt"))]
            for member in members:
                with archive.open(member) as binary:
                    text = io.TextIOWrapper(binary, encoding="latin-1", errors="replace", newline="")
                    reader = csv.DictReader(text, delimiter=";")
                    headers = list(reader.fieldnames or [])
                    document_header = find_matching_header(headers, document_headers)
                    if document_header is None:
                        continue
                    files_scanned += 1
                    for row in reader:
                        rows_scanned += 1
                        if only_digits(row.get(document_header)) != document:
                            continue
                        matches.append(select_csv_fields(row, allowed_headers))
                        if len(matches) >= max_matches:
                            return matches, {
                                "rows_scanned": rows_scanned,
                                "files_scanned": files_scanned,
                                "truncated": True,
                            }, None
        return matches, {
            "rows_scanned": rows_scanned,
            "files_scanned": files_scanned,
            "truncated": False,
        }, None
    except (OSError, UnicodeError, csv.Error, zipfile.BadZipFile) as exc:
        return [], {"rows_scanned": rows_scanned, "files_scanned": files_scanned}, str(exc)


def query_cgu(
    source_id: str,
    document: str,
    cache_dir: Path,
    timeout: float,
    refresh: bool,
) -> dict:
    config = CGU_SOURCES[source_id]
    slug = config["slug"]
    page_url = f"https://portaldatransparencia.gov.br/download-de-dados/{slug}"
    if not config.get("exact_document_available", True):
        api_key = os.environ.get("LUPA_TRANSPARENCIA_API_KEY", "").strip()
        if api_key:
            return query_cgu_key_api(source_id, document, timeout, api_key)
        return result_base(
            source_id, config["name"], page_url, "not_configured",
            details={
                "reason": "O download aberto mascara o CPF; associação parcial foi recusada.",
                "setup": "obtenha a chave gratuita oficial e exporte LUPA_TRANSPARENCIA_API_KEY",
                "key_url": "https://portaldatransparencia.gov.br/api-de-dados/cadastrar-email",
            },
        )
    reference, error = latest_cgu_reference(slug, timeout)
    if error or not reference:
        return result_base(source_id, config["name"], page_url, "error", error=error)

    download_url = f"{page_url}/{reference}"
    zip_path = cache_dir / "cgu" / slug / f"{reference}_{slug.upper()}.zip"
    had_cache = zip_path.exists()
    if refresh:
        zip_path.unlink(missing_ok=True)
        had_cache = False
    if not zip_path.exists():
        _, error = download_dataset(download_url, zip_path, timeout=max(timeout, 45))
        if error:
            return result_base(
                source_id, config["name"], page_url, "error", error=error,
                details={"reference": reference},
            )

    records, scan_details, error = scan_zip_csv_exact(
        zip_path, document, config["document_headers"], config["allowed_headers"]
    )
    details = {"reference": reference, "cache_hit": had_cache, **scan_details}
    if error:
        return result_base(
            source_id, config["name"], page_url, "error", error=error, details=details
        )
    safe_records = sanitize_cpf_value(records, document) if len(document) == 11 else records
    return result_base(
        source_id,
        config["name"],
        page_url,
        "match" if records else "no_match",
        records=safe_records,  # type: ignore[arg-type]
        details=details,
    )


def query_cgu_key_api(source_id: str, document: str, timeout: float, api_key: str) -> dict:
    """Usa a API oficial gratuita quando a base aberta mascara o CPF."""
    config = CGU_SOURCES[source_id]
    if source_id == "cgu_ceaf":
        path, parameter = "ceaf", "cpfSancionado"
    elif source_id == "cgu_pep":
        path, parameter = "peps", "cpf"
    else:
        path, parameter = config["slug"], "codigoSancionado"
    public_url = f"https://api.portaldatransparencia.gov.br/api-de-dados/{path}"
    query = urllib.parse.urlencode({parameter: document, "pagina": 1})
    data, error = http_json(
        f"{public_url}?{query}", timeout=timeout,
        extra_headers={"chave-api-dados": api_key},
    )
    if error:
        return result_base(source_id, config["name"], public_url, "error", error=error)
    if not isinstance(data, list):
        return result_base(
            source_id, config["name"], public_url, "error",
            error="formato de resposta inesperado",
        )
    records = [row for row in data if isinstance(row, dict)]
    records = sanitize_cpf_value(records, document)  # type: ignore[assignment]
    result = result_base(
        source_id, config["name"], public_url,
        "match" if records else "no_match", records=records,
        details={"query": "filtro exato no servidor oficial", "page": 1},
    )
    if records:
        result["match_method"] = "official_exact_document_filter"
        result["confidence"] = 0.99
    return result


def query_cvm_cnpj(cnpj: str, cache_dir: Path, timeout: float, refresh: bool) -> dict:
    """Pesquisa por CNPJ exato no cadastro diário de companhias abertas da CVM."""
    path = cache_dir / "cvm" / "cad_cia_aberta.csv"
    if refresh:
        path.unlink(missing_ok=True)
    cache_hit = path.exists()
    if not path.exists():
        _, error = download_plain_file(CVM_DATASET, path, max(timeout, 45), max_bytes=20 * 1024 * 1024)
        if error:
            return result_base("cvm_cia_aberta", "CVM - cadastro de companhias abertas", CVM_DATASET, "error", error=error)
    records: list[dict] = []
    rows_scanned = 0
    allowed = [
        "CNPJ_CIA", "DENOM_SOCIAL", "DENOM_COMERC", "DT_REG", "DT_CONST", "DT_CANCEL",
        "MOTIVO_CANCEL", "SIT", "DT_INI_SIT", "CD_CVM", "SETOR_ATIV", "TP_MERC",
        "CATEG_REG", "DT_INI_CATEG", "SIT_EMISSOR", "CONTROLE_ACIONARIO", "MUN", "UF",
        "PAIS", "EMAIL", "TP_RESP", "RESP", "DT_INI_RESP", "CNPJ_AUDITOR", "AUDITOR",
    ]
    try:
        with path.open("r", encoding="latin-1", errors="replace", newline="") as stream:
            for row in csv.DictReader(stream, delimiter=";"):
                rows_scanned += 1
                if only_digits(row.get("CNPJ_CIA")) == cnpj:
                    records.append({key: row.get(key) for key in allowed if row.get(key)})
    except (OSError, UnicodeError, csv.Error) as exc:
        return result_base("cvm_cia_aberta", "CVM - cadastro de companhias abertas", CVM_DATASET, "error", error=str(exc))
    return result_base(
        "cvm_cia_aberta", "CVM - cadastro de companhias abertas", CVM_DATASET,
        "match" if records else "no_match", records=records,
        details={"cache_hit": cache_hit, "rows_scanned": rows_scanned},
    )


def query_bcb_cnpj(cnpj: str, timeout: float) -> dict:
    """Consulta a entidade supervisionada do BCB pelo CNPJ-base legalmente comum às filiais."""
    # O serviço oficial exige uma data-base; 31/12 do último ano encerrado é estável.
    base_date = f"12-31-{dt.datetime.now().year - 1}"
    root = cnpj[:8]
    filter_expression = urllib.parse.quote(f"codigoCNPJ8 eq '{root}'", safe="'")
    parameters = (
        f"@dataBase='{base_date}'&%24filter={filter_expression}"
        "&%24top=100&%24format=json"
    )
    endpoint = f"{BCB_ODATA}/EntidadesSupervisionadas(dataBase=@dataBase)?{parameters}"
    data, error = http_json(endpoint, timeout=timeout)
    source_url = "https://dadosabertos.bcb.gov.br/dataset/dados-cadastrais-de-entidades-autorizadas"
    if error:
        return result_base("bcb_entidades", "Banco Central - entidades supervisionadas", source_url, "error", error=error)
    rows = data.get("value", []) if isinstance(data, dict) else []
    verified = [row for row in rows if isinstance(row, dict) and only_digits(row.get("codigoCNPJ8")) == root]
    exact = [row for row in verified if only_digits(row.get("codigoCNPJ14")) == cnpj]
    records = exact or verified
    if not records:
        status = "no_match"
        method = None
        confidence = None
    else:
        status = "match"
        method = "document_exact" if exact else "cnpj_root_exact"
        confidence = 1.0 if exact else 0.98
    result = result_base(
        "bcb_entidades", "Banco Central - entidades supervisionadas", source_url,
        status, records=records,
        details={
            "data_base": base_date,
            "relation": "CNPJ completo" if exact else "mesma raiz de oito dígitos; estabelecimento BCB pode divergir",
        },
    )
    result["match_method"] = method
    result["confidence"] = confidence
    return result


# ---------------------------------------------------------------------------
# Índice local da base completa da Receita Federal
# ---------------------------------------------------------------------------


RFB_LAYOUTS = {
    "empresas": [
        "cnpj_base", "razao_social", "natureza_juridica", "qualificacao_responsavel",
        "capital_social", "porte_empresa", "ente_federativo_responsavel",
    ],
    "estabelecimentos": [
        "cnpj_base", "cnpj_ordem", "cnpj_dv", "matriz_filial", "nome_fantasia",
        "situacao_cadastral", "data_situacao_cadastral", "motivo_situacao_cadastral",
        "nome_cidade_exterior", "pais", "data_inicio_atividade", "cnae_principal",
        "cnaes_secundarios", "tipo_logradouro", "logradouro", "numero", "complemento",
        "bairro", "cep", "uf", "municipio", "ddd1", "telefone1", "ddd2", "telefone2",
        "ddd_fax", "fax", "email", "situacao_especial", "data_situacao_especial",
    ],
    "socios": [
        "cnpj_base", "identificador_socio", "nome_socio", "cpf_cnpj_socio",
        "qualificacao_socio", "data_entrada", "pais", "representante_legal",
        "nome_representante", "qualificacao_representante", "faixa_etaria",
    ],
    "simples": [
        "cnpj_base", "opcao_simples", "data_opcao_simples", "data_exclusao_simples",
        "opcao_mei", "data_opcao_mei", "data_exclusao_mei",
    ],
}


def classify_rfb_file(container_name: str, member_name: str = "") -> tuple[str | None, str | None]:
    name = f"{container_name} {member_name}".upper()
    for marker, kind in (
        ("ESTABELE", "estabelecimentos"), ("EMPRE", "empresas"),
        ("SOCIO", "socios"), ("SIMPLES", "simples"),
    ):
        if marker in name:
            return kind, None
    for marker, lookup in (
        ("CNAE", "cnae"), ("MUNIC", "municipio"), ("NATJU", "natureza_juridica"),
        ("QUALS", "qualificacao"), ("PAIS", "pais"), ("MOTI", "motivo"),
    ):
        if marker in name:
            return "lookup", lookup
    return None, None


def _rfb_insert_rows(
    connection: sqlite3.Connection,
    kind: str,
    lookup_kind: str | None,
    reader: object,
) -> tuple[int, int]:
    inserted = 0
    rejected = 0
    layout = RFB_LAYOUTS.get(kind)
    for raw in reader:  # type: ignore[union-attr]
        if not isinstance(raw, list):
            rejected += 1
            continue
        values = [str(value).strip() for value in raw]
        if kind == "lookup":
            if len(values) < 2 or not lookup_kind:
                rejected += 1
                continue
            connection.execute(
                "INSERT OR REPLACE INTO lookups(kind, code, label) VALUES (?, ?, ?)",
                (lookup_kind, values[0], values[1]),
            )
        elif layout and len(values) >= len(layout):
            record = dict(zip(layout, values[: len(layout)]))
            payload = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            root = record["cnpj_base"]
            if len(root) != 8 or not root.isdigit():
                rejected += 1
                continue
            if kind == "empresas":
                connection.execute("INSERT OR REPLACE INTO empresas VALUES (?, ?)", (root, payload))
            elif kind == "estabelecimentos":
                cnpj = root + record["cnpj_ordem"] + record["cnpj_dv"]
                if len(cnpj) != 14 or not cnpj.isdigit():
                    rejected += 1
                    continue
                connection.execute(
                    "INSERT OR REPLACE INTO estabelecimentos VALUES (?, ?, ?)",
                    (cnpj, root, payload),
                )
            elif kind == "socios":
                fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                connection.execute(
                    "INSERT OR REPLACE INTO socios(cnpj_base, fingerprint, data_json) VALUES (?, ?, ?)",
                    (root, fingerprint, payload),
                )
            elif kind == "simples":
                connection.execute("INSERT OR REPLACE INTO simples VALUES (?, ?)", (root, payload))
        else:
            rejected += 1
            continue
        inserted += 1
        if inserted % 50000 == 0:
            connection.commit()
    return inserted, rejected


def build_rfb_index(source_dir: Path, cache_dir: Path) -> int:
    """Constrói SQLite atômico a partir dos ZIPs oficiais já baixados da RFB."""
    if not source_dir.is_dir():
        print(f"{R}[-] Diretório da Receita Federal não encontrado: {source_dir}{W}")
        return 2
    candidates = sorted(path for path in source_dir.iterdir() if path.is_file())
    if not candidates:
        print(f"{R}[-] Nenhum arquivo encontrado em {source_dir}.{W}")
        return 2
    cache_dir.mkdir(parents=True, exist_ok=True)
    final_path = cache_dir / "rfb.sqlite"
    temporary = cache_dir / "rfb.sqlite.building"
    temporary.unlink(missing_ok=True)
    connection = sqlite3.connect(temporary)
    try:
        connection.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE empresas(cnpj_base TEXT PRIMARY KEY, data_json TEXT NOT NULL);
            CREATE TABLE estabelecimentos(cnpj TEXT PRIMARY KEY, cnpj_base TEXT NOT NULL, data_json TEXT NOT NULL);
            CREATE INDEX estabelecimentos_base ON estabelecimentos(cnpj_base);
            CREATE TABLE socios(cnpj_base TEXT NOT NULL, fingerprint TEXT NOT NULL, data_json TEXT NOT NULL,
                                PRIMARY KEY(cnpj_base, fingerprint));
            CREATE TABLE simples(cnpj_base TEXT PRIMARY KEY, data_json TEXT NOT NULL);
            CREATE TABLE lookups(kind TEXT NOT NULL, code TEXT NOT NULL, label TEXT NOT NULL,
                                 PRIMARY KEY(kind, code));
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """
        )
        total = rejected = files = 0
        for path in candidates:
            if path.suffix.lower() == ".zip":
                try:
                    with zipfile.ZipFile(path) as archive:
                        for member in archive.namelist():
                            if member.endswith("/"):
                                continue
                            kind, lookup_kind = classify_rfb_file(path.name, member)
                            if not kind:
                                continue
                            print(f"  [RFB] {path.name} :: {member} ({kind})")
                            with archive.open(member) as binary:
                                text_stream = io.TextIOWrapper(binary, encoding="latin-1", errors="replace", newline="")
                                count, bad = _rfb_insert_rows(
                                    connection, kind, lookup_kind, csv.reader(text_stream, delimiter=";")
                                )
                            total += count
                            rejected += bad
                            files += 1
                except (OSError, zipfile.BadZipFile, csv.Error) as exc:
                    print(f"{Y}[!] Arquivo ignorado ({path.name}): {exc}{W}")
            else:
                kind, lookup_kind = classify_rfb_file(path.name)
                if not kind:
                    continue
                print(f"  [RFB] {path.name} ({kind})")
                with path.open("r", encoding="latin-1", errors="replace", newline="") as stream:
                    count, bad = _rfb_insert_rows(
                        connection, kind, lookup_kind, csv.reader(stream, delimiter=";")
                    )
                total += count
                rejected += bad
                files += 1
        if not files:
            raise ValueError("nenhum arquivo com nome/layout reconhecido")
        connection.execute("INSERT INTO metadata VALUES ('built_at', ?)", (utc_now(),))
        connection.execute("INSERT INTO metadata VALUES ('source_dir', ?)", (str(source_dir.resolve()),))
        connection.execute("INSERT INTO metadata VALUES ('records', ?)", (str(total),))
        connection.commit()
        connection.close()
        os.replace(temporary, final_path)
        print(f"{G}[+] Índice RFB pronto: {final_path} ({total} linhas; {rejected} rejeitadas){W}")
        return 0
    except (OSError, sqlite3.Error, ValueError, csv.Error) as exc:
        connection.close()
        temporary.unlink(missing_ok=True)
        print(f"{R}[-] Falha ao construir índice RFB: {exc}{W}")
        return 1


def query_rfb_index(cnpj: str, cache_dir: Path) -> dict:
    path = cache_dir / "rfb.sqlite"
    source_url = "https://dados.gov.br/dados/conjuntos-dados/cadastro-nacional-da-pessoa-juridica---cnpj"
    if not path.exists():
        return result_base(
            "rfb_cnpj_completo", "Receita Federal - dados abertos completos", source_url,
            "not_configured",
            details={
                "reason": "índice local ainda não construído",
                "setup": "baixe os ZIPs oficiais e execute lupa --build-rfb-index DIRETORIO",
            },
        )
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        establishment_row = connection.execute(
            "SELECT data_json FROM estabelecimentos WHERE cnpj = ?", (cnpj,)
        ).fetchone()
        if not establishment_row:
            connection.close()
            return result_base(
                "rfb_cnpj_completo", "Receita Federal - dados abertos completos", source_url,
                "no_match", details={"index": str(path)},
            )
        root = cnpj[:8]
        company_row = connection.execute(
            "SELECT data_json FROM empresas WHERE cnpj_base = ?", (root,)
        ).fetchone()
        simple_row = connection.execute(
            "SELECT data_json FROM simples WHERE cnpj_base = ?", (root,)
        ).fetchone()
        partner_rows = connection.execute(
            "SELECT data_json FROM socios WHERE cnpj_base = ? ORDER BY fingerprint", (root,)
        ).fetchall()
        metadata = dict(connection.execute("SELECT key, value FROM metadata").fetchall())
        connection.close()
        record = {
            "empresa": json.loads(company_row[0]) if company_row else None,
            "estabelecimento": json.loads(establishment_row[0]),
            "simples_mei": json.loads(simple_row[0]) if simple_row else None,
            "socios": [json.loads(row[0]) for row in partner_rows],
        }
        return result_base(
            "rfb_cnpj_completo", "Receita Federal - dados abertos completos", source_url,
            "match", records=[record], details={"index": str(path), **metadata},
        )
    except (OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        return result_base(
            "rfb_cnpj_completo", "Receita Federal - dados abertos completos", source_url,
            "error", error=str(exc),
        )


# ---------------------------------------------------------------------------
# Índice incremental do Portal Nacional de Contratações Públicas
# ---------------------------------------------------------------------------


def local_secret(cache_dir: Path) -> bytes:
    path = cache_dir / ".local-secret"
    cache_key = str(path.resolve())
    if cache_key in _LOCAL_SECRET_CACHE:
        return _LOCAL_SECRET_CACHE[cache_key]
    cache_dir.mkdir(parents=True, exist_ok=True)
    if path.exists():
        secret = path.read_bytes()
        _LOCAL_SECRET_CACHE[cache_key] = secret
        return secret
    secret = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        secret = path.read_bytes()
        _LOCAL_SECRET_CACHE[cache_key] = secret
        return secret
    try:
        os.write(descriptor, secret)
    finally:
        os.close(descriptor)
    _LOCAL_SECRET_CACHE[cache_key] = secret
    return secret


def document_token(document: str, cache_dir: Path) -> str:
    return hmac.new(local_secret(cache_dir), document.encode("ascii"), hashlib.sha256).hexdigest()


def pncp_connection(cache_dir: Path) -> sqlite3.Connection:
    cache_dir.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(cache_dir / "pncp.sqlite")
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS contracts(
          subject_token TEXT NOT NULL,
          record_id TEXT NOT NULL,
          role TEXT NOT NULL,
          data_json TEXT NOT NULL,
          PRIMARY KEY(subject_token, record_id, role)
        );
        CREATE TABLE IF NOT EXISTS pncp_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """
    )
    return connection


def sync_pncp(days: int, cache_dir: Path, timeout: float) -> int:
    if days < 1 or days > 3650:
        print(f"{R}[-] --sync-pncp-days deve estar entre 1 e 3650.{W}")
        return 2
    connection = pncp_connection(cache_dir)
    end = dt.datetime.now().date()
    start = end - dt.timedelta(days=days - 1)
    stored = 0
    failed_dates: list[str] = []
    try:
        current = start
        while current <= end:
            page = 1
            total_pages = 1
            while page <= total_pages:
                query = urllib.parse.urlencode(
                    {
                        "dataInicial": current.strftime("%Y%m%d"),
                        "dataFinal": current.strftime("%Y%m%d"),
                        "pagina": page,
                        "tamanhoPagina": 500,
                    }
                )
                data, error = http_json(f"{PNCP_API}?{query}", timeout=max(timeout, 45))
                if error:
                    print(f"{Y}[!] PNCP {current} página {page}: {error}{W}")
                    failed_dates.append(current.isoformat())
                    break
                if not isinstance(data, dict):
                    print(f"{Y}[!] PNCP {current}: resposta inesperada{W}")
                    failed_dates.append(current.isoformat())
                    break
                rows = data.get("data") or []
                total_pages = int(data.get("totalPaginas") or 0)
                for row in rows if isinstance(rows, list) else []:
                    if not isinstance(row, dict):
                        continue
                    record_id = str(
                        row.get("numeroControlePNCP")
                        or row.get("numeroControlePncpCompra")
                        or hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
                    )
                    subjects = [
                        (only_digits(row.get(field)), role)
                        for field, role in (
                            ("niFornecedor", "fornecedor"),
                            ("niFornecedorSubContratado", "subcontratado"),
                        )
                    ]
                    safe_row: object = row
                    for candidate, _ in subjects:
                        if len(candidate) == 11:
                            safe_row = sanitize_cpf_value(safe_row, candidate)
                    for document, role in subjects:
                        if len(document) not in {11, 14}:
                            continue
                        connection.execute(
                            "INSERT OR REPLACE INTO contracts VALUES (?, ?, ?, ?)",
                            (
                                document_token(document, cache_dir), record_id, role,
                                json.dumps(safe_row, ensure_ascii=False, separators=(",", ":")),
                            ),
                        )
                        stored += 1
                connection.commit()
                page += 1
            print(f"  [PNCP] {current}: {max(0, total_pages)} página(s)")
            current += dt.timedelta(days=1)
        connection.execute(
            "INSERT OR REPLACE INTO pncp_metadata VALUES ('last_sync', ?)", (utc_now(),)
        )
        connection.execute(
            "INSERT OR REPLACE INTO pncp_metadata VALUES ('covered_from', ?)", (start.isoformat(),)
        )
        connection.execute(
            "INSERT OR REPLACE INTO pncp_metadata VALUES ('covered_to', ?)", (end.isoformat(),)
        )
        connection.execute(
            "INSERT OR REPLACE INTO pncp_metadata VALUES ('failed_dates', ?)",
            (json.dumps(sorted(set(failed_dates))),),
        )
        connection.commit()
        print(f"{G}[+] PNCP sincronizado: {stored} vínculo(s) indexado(s); {len(set(failed_dates))} dia(s) com falha.{W}")
        return 0 if not failed_dates else 1
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"{R}[-] Falha na sincronização PNCP: {exc}{W}")
        return 1
    finally:
        connection.close()


def query_pncp_index(document: str, cache_dir: Path) -> dict:
    path = cache_dir / "pncp.sqlite"
    source_url = "https://pncp.gov.br/app/dados-abertos"
    if not path.exists():
        return result_base(
            "pncp_contratos", "PNCP - contratos", source_url, "not_configured",
            details={"setup": "execute lupa --sync-pncp-days N para criar/atualizar o índice local"},
        )
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        rows = connection.execute(
            "SELECT role, data_json FROM contracts WHERE subject_token = ? ORDER BY record_id",
            (document_token(document, cache_dir),),
        ).fetchall()
        metadata = dict(connection.execute("SELECT key, value FROM pncp_metadata").fetchall())
        connection.close()
        records = []
        for role, payload in rows:
            record = json.loads(payload)
            record["_lupa_role"] = role
            records.append(record)
        if len(document) == 11:
            records = sanitize_cpf_value(records, document)  # type: ignore[assignment]
        return result_base(
            "pncp_contratos", "PNCP - contratos", source_url,
            "match" if records else "no_match", records=records,
            details={"index": str(path), **metadata},
        )
    except (OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        return result_base("pncp_contratos", "PNCP - contratos", source_url, "error", error=str(exc))


TSE_ALLOWED_HEADERS = [
    "ANO_ELEICAO", "NM_TIPO_ELEICAO", "SG_UF", "NM_UE", "NM_CANDIDATO",
    "NM_URNA_CANDIDATO", "DS_CARGO", "NR_CANDIDATO", "SG_PARTIDO", "NM_PARTIDO",
    "DS_SITUACAO_CANDIDATURA", "DS_DETALHE_SITUACAO_CAND", "DS_OCUPACAO",
    "DS_GRAU_INSTRUCAO", "SQ_CANDIDATO",
]


def query_tse_year(
    year: int,
    cpf: str,
    cache_dir: Path,
    timeout: float,
    refresh: bool,
) -> dict:
    source_id = f"tse_candidatos_{year}"
    source_name = f"TSE - Candidaturas {year}"
    url = f"https://cdn.tse.jus.br/estatistica/sead/odsele/consulta_cand/consulta_cand_{year}.zip"
    zip_path = cache_dir / "tse" / f"consulta_cand_{year}.zip"
    if refresh:
        zip_path.unlink(missing_ok=True)
    if not zip_path.exists():
        _, error = download_dataset(url, zip_path, timeout=max(timeout, 45))
        if error:
            return result_base(source_id, source_name, url, "error", error=error)
    records, details, error = scan_zip_csv_exact(
        zip_path, cpf, ["NR_CPF_CANDIDATO"], TSE_ALLOWED_HEADERS
    )
    details["year"] = year
    if error:
        return result_base(source_id, source_name, url, "error", error=error, details=details)
    return result_base(
        source_id,
        source_name,
        url,
        "match" if records else "no_match",
        records=sanitize_cpf_value(records, cpf),
        details=details,
    )


def default_tse_years() -> list[int]:
    year = dt.datetime.now().year
    if year % 2:
        year -= 1
    return [year - offset for offset in (0, 2, 4)]


def manual_cpf_sources() -> list[dict]:
    return [
        result_base(
            "receita_cpf",
            "Receita Federal - Comprovante de Situação Cadastral no CPF",
            "https://servicos.receita.fazenda.gov.br/Servicos/CPF/ConsultaSituacao/ConsultaPublica.asp",
            "manual",
            details={
                "reason": "A consulta oficial exige data de nascimento e validação humana; a LUPA não contorna CAPTCHA nem coleta esse dado adicional."
            },
        )
    ]


def collect_exact_names(results: list[dict]) -> list[dict]:
    name_keys = {
        "nome", "nomedosancionado", "nomeinformadopeloorgaosancionador",
        "nomepep", "nmcandidato",
    }
    grouped: dict[str, dict] = {}
    for result in results:
        if result.get("status") != "match":
            continue
        for record in result.get("records", []):
            if not isinstance(record, dict):
                continue
            for key, value in record.items():
                if normalize_header(key) not in name_keys or not str(value).strip():
                    continue
                normalized = normalize_text(value)
                if not normalized:
                    continue
                item = grouped.setdefault(
                    normalized,
                    {"name": str(value).strip(), "sources": [], "match_method": "document_exact"},
                )
                if result["source_id"] not in item["sources"]:
                    item["sources"].append(result["source_id"])
    return sorted(grouped.values(), key=lambda item: (-len(item["sources"]), item["name"]))


def build_person_graph(report: dict, output_path: Path) -> None:
    lines = ["graph TD"]
    target = report["target"]["masked_document"]
    lines.append(f'    CPF["Pessoa consultada<br/>{target}"]')
    for index, identity in enumerate(report.get("verified_identities", [])[:5]):
        safe_name = str(identity["name"]).replace('"', "'")
        node = f"Name_{index}"
        lines.append(f'    {node}["{safe_name}"]')
        lines.append(f"    CPF -->|documento exato| {node}")
    matched = [result for result in report["sources"] if result.get("status") == "match"]
    for index, result in enumerate(matched):
        node = f"Source_{index}"
        label = str(result["source_name"]).replace('"', "'")
        count = len(result.get("records", []))
        lines.append(f'    {node}["{label}<br/>{count} registro(s)"]')
        lines.append(f"    CPF -->|CPF confirmado pela fonte| {node}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def history_projection(report: dict) -> dict:
    sources = {
        str(item.get("source_id")): {
            "status": item.get("status"),
            "records": len(item.get("records", [])),
        }
        for item in report.get("sources", []) if isinstance(item, dict)
    }
    canonical = report.get("canonical") or {}
    selected = {
        key: canonical.get(key)
        for key in (
            "razao_social", "nome_fantasia", "descricao_situacao_cadastral",
            "capital_social", "email", "municipio", "uf", "cnae_fiscal",
        )
        if isinstance(canonical, dict) and key in canonical
    }
    return {"sources": sources, "canonical": selected}


def save_history(report: dict, document: str, cache_dir: Path) -> dict:
    """Mantém snapshots comparáveis; CPF é indexado somente por HMAC local."""
    token = document_token(document, cache_dir)
    directory = cache_dir / "history" / token
    directory.mkdir(parents=True, exist_ok=True)
    previous_files = sorted(directory.glob("*.json"))
    current_projection = history_projection(report)
    changes: list[dict] = []
    previous_at = None
    if previous_files:
        try:
            previous = json.loads(previous_files[-1].read_text(encoding="utf-8"))
            previous_at = previous.get("generated_at")
            old_projection = history_projection(previous)
            old_sources = old_projection.get("sources", {})
            new_sources = current_projection.get("sources", {})
            for source_id in sorted(set(old_sources) | set(new_sources)):
                if old_sources.get(source_id) != new_sources.get(source_id):
                    changes.append(
                        {"path": f"sources.{source_id}", "before": old_sources.get(source_id), "after": new_sources.get(source_id)}
                    )
            old_canonical = old_projection.get("canonical", {})
            new_canonical = current_projection.get("canonical", {})
            for field in sorted(set(old_canonical) | set(new_canonical)):
                if old_canonical.get(field) != new_canonical.get(field):
                    changes.append(
                        {"path": f"canonical.{field}", "before": old_canonical.get(field), "after": new_canonical.get(field)}
                    )
        except (OSError, json.JSONDecodeError):
            changes.append({"path": "history", "warning": "snapshot anterior ilegível"})
    history = {
        "previous_generated_at": previous_at,
        "changes_since_previous": changes[:100],
        "changed": bool(changes),
        "identifier_storage": "HMAC-SHA256 com segredo local; documento não usado no caminho",
    }
    report["history"] = history
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S_%f")
    (directory / f"{stamp}.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return history


def confirm_lawful_use(args: argparse.Namespace) -> bool:
    if args.no_network or args.ack_lawful_use:
        return True
    message = (
        "O modo CPF consulta fontes oficiais usando o documento exato. "
        "Use apenas com finalidade legítima, base legal aplicável e respeito à LGPD."
    )
    print(f"{Y}[!] {message}{W}")
    if not sys.stdin.isatty():
        print(f"{R}[-] Em execução não interativa, informe --ack-lawful-use.{W}")
        return False
    answer = input("Digite SIM para confirmar e continuar: ").strip().upper()
    return answer == "SIM"


def run_cpf(args: argparse.Namespace, cpf: str) -> int:
    if not validate_cpf(cpf):
        print(f"{R}[-] CPF inválido: quantidade, repetição ou dígitos verificadores incorretos.{W}")
        return 2
    if not confirm_lawful_use(args):
        print(f"{R}[-] Consulta cancelada.{W}")
        return 2

    banner("CPF")
    print(f"{G}[✓] CPF validado localmente: {mask_cpf(cpf)}{W}")
    print(f"{C}[*] Regra de vínculo: somente correspondência exata do documento.{W}")

    results: list[dict] = []
    if args.no_network:
        results.append(
            result_base(
                "validation_only",
                "Validação local de CPF",
                "local://cpf-checksum",
                "no_match",
                details={"network_disabled": True},
            )
        )
    else:
        jobs: list[tuple[str, object]] = []
        if not args.skip_tcu:
            for source_id in TCU_SOURCES:
                jobs.append((source_id, lambda sid=source_id: query_tcu(sid, cpf, args.timeout)))
        if not args.skip_cgu:
            for source_id, config in CGU_SOURCES.items():
                if "cpf" not in config.get("document_types", ["cpf"]):
                    continue
                jobs.append(
                    (
                        source_id,
                        lambda sid=source_id: query_cgu(
                            sid, cpf, args.cache_dir, args.timeout, args.refresh_cache
                        ),
                    )
                )
        if not args.skip_compras:
            jobs.append(
                ("compras_fornecedor", lambda: query_compras_supplier(cpf, "cpf", args.timeout))
            )
        if not args.skip_pncp:
            jobs.append(("pncp_contratos", lambda: query_pncp_index(cpf, args.cache_dir)))
        if not args.skip_tse:
            for year in args.tse_years:
                jobs.append(
                    (
                        f"tse_candidatos_{year}",
                        lambda y=year: query_tse_year(
                            y, cpf, args.cache_dir, args.timeout, args.refresh_cache
                        ),
                    )
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, max(1, len(jobs)))) as executor:
            futures = {
                executor.submit(timed_call, callable_job): source_id
                for source_id, callable_job in jobs
            }
            for future in concurrent.futures.as_completed(futures):
                source_id = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # isolamento: uma fonte não derruba a consulta
                    result = result_base(source_id, source_id, "", "error", error=str(exc))
                results.append(result)
                status = result["status"]
                if status == "match":
                    print(f"  {G}[+] {result['source_name']}: {len(result['records'])} registro(s) exato(s){W}")
                elif status == "no_match":
                    print(f"  [=] {result['source_name']}: nenhum registro exato")
                elif status == "not_queryable_exact":
                    print(f"  {Y}[i] {result['source_name']}: base mascara o CPF; sem associação parcial{W}")
                elif status == "not_configured":
                    print(f"  {Y}[i] {result['source_name']}: fonte gratuita/índice ainda não configurado{W}")
                else:
                    print(f"  {Y}[!] {result['source_name']}: {result.get('error', status)}{W}")

    results.extend(manual_cpf_sources())
    results = deduplicate_records(results)
    results.sort(key=lambda item: item["source_id"])
    verified_identities = collect_exact_names(results)
    matched_sources = sum(1 for result in results if result["status"] == "match")
    matched_records = sum(
        len(result.get("records", [])) for result in results if result["status"] == "match"
    )
    error_sources = sum(1 for result in results if result["status"] == "error")
    not_queryable_sources = sum(
        1 for result in results if result["status"] == "not_queryable_exact"
    )
    not_configured_sources = sum(
        1 for result in results if result["status"] == "not_configured"
    )

    report_id = secrets.token_hex(8)
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "LUPA", "version": VERSION},
        "report_id": report_id,
        "generated_at": utc_now(),
        "target": {
            "type": "CPF",
            "masked_document": mask_cpf(cpf),
            "checksum_valid": True,
            "raw_document_persisted": False,
        },
        "matching_policy": {
            "accepted": "document_exact",
            "rejected": ["name_only", "fuzzy_name", "first_name", "unverified_search_result"],
        },
        "summary": {
            "matched_sources": matched_sources,
            "matched_records": matched_records,
            "source_errors": error_sources,
            "sources_not_queryable_exact": not_queryable_sources,
            "sources_not_configured": not_configured_sources,
            "absence_is_not_clearance_certificate": True,
            "source_statuses": source_status_summary(results),
        },
        "verified_identities": verified_identities,
        "sources": results,
        "privacy": {
            "raw_cpf_not_logged": True,
            "raw_cpf_not_exported": True,
            "datasets_cached": "Bases públicas são armazenadas no cache local; use --refresh-cache para atualizar.",
        },
    }
    report = sanitize_cpf_value(report, cpf)  # type: ignore[assignment]
    save_history(report, cpf, args.cache_dir)
    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    if cpf in serialized or format_cpf(cpf) in serialized:
        print(f"{R}[-] Proteção de privacidade bloqueou a exportação do CPF bruto.{W}")
        return 3

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"relatorio_cpf_final_{cpf[-2:]}_{stamp}_{report_id[:6]}"
    json_path = args.output_dir / f"{base_name}.json"
    graph_path = args.output_dir / f"{base_name}_grafo.mmd"
    json_path.write_text(serialized + "\n", encoding="utf-8")
    build_person_graph(report, graph_path)

    print(f"\n{C}[!] RESUMO CPF{W}")
    print(f"  Fontes com correspondência exata : {matched_sources}")
    print(f"  Registros confirmados            : {matched_records}")
    print(f"  Fontes indisponíveis/com erro    : {error_sources}")
    print(f"  Fontes com CPF público mascarado : {not_queryable_sources}")
    print(f"  Fontes/índices não configurados  : {not_configured_sources}")
    if verified_identities:
        print("  Identidade(s) confirmada(s) pelo documento:")
        for identity in verified_identities[:8]:
            print(f"    -> {identity['name']} ({len(identity['sources'])} fonte(s))")
    print(f"\n{G}[+] Relatório JSON: {json_path.resolve()}{W}")
    print(f"{G}[+] Grafo Mermaid: {graph_path.resolve()}{W}")
    print(f"{Y}[!] Ausência de achado não equivale a certidão negativa.{W}\n")
    return 0


# ---------------------------------------------------------------------------
# Modo CNPJ: capacidades históricas preservadas com política anti-falso positivo
# ---------------------------------------------------------------------------


def normalize_cnpj_api(source_name: str, raw: object, cnpj: str) -> dict | None:
    if not isinstance(raw, dict):
        return None
    if source_name in {"BrasilAPI", "MinhaReceita"}:
        returned = only_digits(raw.get("cnpj"))
        if returned and returned != cnpj:
            return None
        if not raw.get("razao_social"):
            return None
        data = dict(raw)
        data["cnpj"] = cnpj
        if "qsa" not in data and isinstance(data.get("socios"), list):
            data["qsa"] = data["socios"]
        return data
    establishment = raw.get("estabelecimento")
    if source_name != "CNPJ.ws" or not isinstance(establishment, dict):
        return None
    returned = only_digits(establishment.get("cnpj") or cnpj)
    if returned != cnpj:
        return None
    activity = establishment.get("atividade_principal") or {}
    city = establishment.get("cidade") or {}
    state = establishment.get("estado") or {}
    return {
        "cnpj": cnpj,
        "razao_social": raw.get("razao_social", ""),
        "nome_fantasia": establishment.get("nome_fantasia", ""),
        "descricao_situacao_cadastral": establishment.get("situacao_cadastral", ""),
        "data_situacao_cadastral": establishment.get("data_situacao_cadastral", ""),
        "data_inicio_atividade": establishment.get("data_inicio_atividade", ""),
        "natureza_juridica": (raw.get("natureza_juridica") or {}).get("descricao", "")
        if isinstance(raw.get("natureza_juridica"), dict) else raw.get("natureza_juridica", ""),
        "capital_social": float(raw.get("capital_social") or 0),
        "porte": (raw.get("porte") or {}).get("descricao", "")
        if isinstance(raw.get("porte"), dict) else raw.get("porte", ""),
        "email": establishment.get("email", ""),
        "ddd_telefone_1": f"{establishment.get('ddd1') or ''}{establishment.get('telefone1') or ''}",
        "ddd_telefone_2": f"{establishment.get('ddd2') or ''}{establishment.get('telefone2') or ''}",
        "tipo_logradouro": establishment.get("tipo_logradouro", ""),
        "logradouro": establishment.get("logradouro", ""),
        "numero": establishment.get("numero", ""),
        "complemento": establishment.get("complemento", ""),
        "bairro": establishment.get("bairro", ""),
        "municipio": city.get("nome", "") if isinstance(city, dict) else "",
        "codigo_municipio_ibge": city.get("ibge_id", "") if isinstance(city, dict) else "",
        "uf": state.get("sigla", "") if isinstance(state, dict) else "",
        "cep": establishment.get("cep", ""),
        "cnae_fiscal": activity.get("id", "") if isinstance(activity, dict) else "",
        "cnae_fiscal_descricao": activity.get("descricao", "") if isinstance(activity, dict) else "",
        "cnaes_secundarios": [
            {"codigo": item.get("id"), "descricao": item.get("descricao")}
            for item in establishment.get("atividades_secundarias", []) if isinstance(item, dict)
        ],
        "qsa": [
            {
                "nome_socio": item.get("nome"),
                "qualificacao_socio": (item.get("qualificacao_socio") or {}).get("descricao")
                if isinstance(item.get("qualificacao_socio"), dict) else item.get("qualificacao_socio"),
                "data_entrada_sociedade": item.get("data_entrada"),
            }
            for item in raw.get("socios", []) if isinstance(item, dict)
        ],
    }


def _merge_list_values(records: list[tuple[str, dict]], field: str) -> list[object]:
    merged: list[object] = []
    seen: set[str] = set()
    for _, record in records:
        values = record.get(field) or []
        if not isinstance(values, list):
            continue
        for value in values:
            if field == "qsa" and isinstance(value, dict):
                key = "qsa:" + normalize_text(value.get("nome_socio")) + ":" + normalize_text(
                    value.get("qualificacao_socio")
                )
            elif field == "cnaes_secundarios" and isinstance(value, dict):
                key = "cnae:" + only_digits(value.get("codigo") or value.get("id"))
            else:
                key = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                merged.append(value)
    return merged


def aggregate_cnpj_records(records: list[tuple[str, dict]], cnpj: str) -> dict:
    """Cria visão canônica, votos por campo e divergências sem ocultar a origem."""
    preferred = {"BrasilAPI": 0, "MinhaReceita": 1, "CNPJ.ws": 2}
    all_fields = sorted({key for _, record in records for key in record if not key.startswith("_")})
    canonical: dict[str, object] = {"cnpj": cnpj}
    consensus: dict[str, dict] = {}
    divergences: dict[str, list[dict]] = {}
    for field in all_fields:
        if field in {"qsa", "cnaes_secundarios", "socios"}:
            canonical[field] = _merge_list_values(records, field)
            continue
        candidates: dict[str, dict] = {}
        for source, record in records:
            value = record.get(field)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, str):
                if field in {"cnae_fiscal", "codigo_municipio_ibge"} and only_digits(value):
                    key = f"code:{only_digits(value)}"
                else:
                    key = normalize_text(value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                key = (
                    f"code:{only_digits(value)}"
                    if field in {"cnae_fiscal", "codigo_municipio_ibge"}
                    else f"number:{float(value):.12g}"
                )
            else:
                key = json.dumps(value, sort_keys=True, default=str)
            item = candidates.setdefault(key, {"value": value, "sources": []})
            item["sources"].append(source)
        if not candidates:
            continue
        ordered = sorted(
            candidates.values(),
            key=lambda item: (
                -len(item["sources"]),
                min(preferred.get(source, 99) for source in item["sources"]),
            ),
        )
        winner = ordered[0]
        canonical[field] = winner["value"]
        consensus[field] = {"sources": winner["sources"], "votes": len(winner["sources"])}
        if len(ordered) > 1:
            divergences[field] = ordered
    canonical["_lupa_consensus"] = {
        "queried_at": utc_now(),
        "successful_sources": [source for source, _ in records],
        "field_consensus": consensus,
        "divergences": divergences,
    }
    canonical["_lupa_source_records"] = {source: record for source, record in records}
    return canonical


def consultar_cnpj_multi_api(cnpj: str, timeout: float = 12) -> tuple[dict | None, str | None]:
    print(f"{Y}[*] Coletando e comparando todas as APIs cadastrais públicas...{W}")
    sources = [
        ("BrasilAPI", f"https://brasilapi.com.br/api/cnpj/v1/{cnpj}"),
        ("MinhaReceita", f"https://minhareceita.org/{cnpj}"),
        ("CNPJ.ws", f"https://publica.cnpj.ws/cnpj/{cnpj}"),
    ]

    def fetch(source_name: str, url: str) -> tuple[str, str, object | None, str | None, int]:
        started = time.monotonic()
        raw, error = http_json(url, timeout=timeout)
        return source_name, url, raw, error, round((time.monotonic() - started) * 1000)

    collected: list[tuple[str, dict]] = []
    statuses: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = [executor.submit(fetch, name, url) for name, url in sources]
        for future in concurrent.futures.as_completed(futures):
            source_name, url, raw, error, latency = future.result()
            normalized = normalize_cnpj_api(source_name, raw, cnpj)
            if normalized:
                normalized["_lupa_provenance"] = {
                    "source": source_name, "source_url": url,
                    "match_method": "document_exact", "queried_at": utc_now(),
                }
                collected.append((source_name, normalized))
                statuses.append({"source": source_name, "status": "match", "latency_ms": latency})
                print(f"  {G}[+] {source_name}: CNPJ exato confirmado{W}")
            else:
                status = "error" if error else "discarded_or_no_match"
                statuses.append({"source": source_name, "status": status, "error": error, "latency_ms": latency})
                print(f"  {Y}[!] {source_name}: {error or 'sem resposta exata'}{W}")
    if not collected:
        return None, None
    collected.sort(key=lambda item: {"BrasilAPI": 0, "MinhaReceita": 1, "CNPJ.ws": 2}.get(item[0], 99))
    aggregate = aggregate_cnpj_records(collected, cnpj)
    aggregate["_lupa_api_health"] = statuses
    return aggregate, "consenso: " + ", ".join(source for source, _ in collected)


def buscar_historico_wayback(domain: str, timeout: float = 10) -> list[dict]:
    print(f"\n{C}[!] WAYBACK MACHINE CDX (capturas históricas): {domain}{W}")
    query = urllib.parse.quote(f"*.{domain}/*", safe="*./")
    url = f"https://web.archive.org/cdx/search/cdx?url={query}&output=json&fl=original,timestamp,mimetype,statuscode&limit=20"
    data = make_http_request(url, timeout=timeout)
    records: list[dict] = []
    if isinstance(data, list) and len(data) > 1:
        for row in data[1:10]:
            if not isinstance(row, list) or len(row) < 4:
                continue
            record = {"url": row[0], "timestamp": row[1], "mimetype": row[2], "status": row[3]}
            records.append(record)
            print(f"     -> [{str(row[1])[:8]}] ({row[3]}) {row[0]}")
    else:
        print("  -> Nenhuma captura histórica retornada.")
    return records


def verified_github_orgs(company_name: str, confirmed_domains: list[str], timeout: float = 8) -> list[dict]:
    print(f"\n{C}[!] GITHUB ORGANIZATIONS (somente correspondência verificável){W}")
    query = urllib.parse.quote(f'"{company_name}" type:org')
    search_url = f"https://api.github.com/search/users?q={query}&per_page=10"
    data = make_http_request(search_url, timeout=timeout)
    verified: list[dict] = []
    expected = normalize_text(company_name)
    expected_base = re.sub(r"\b(sa|s a|ltda|eireli|me|epp)\b", "", expected).strip()
    domains = {domain.lower().removeprefix("www.") for domain in confirmed_domains}
    if isinstance(data, dict):
        for item in data.get("items", [])[:10]:
            if not isinstance(item, dict) or not item.get("login"):
                continue
            profile = make_http_request(str(item.get("url")), timeout=timeout)
            if not isinstance(profile, dict):
                continue
            profile_name = normalize_text(profile.get("name"))
            profile_company = normalize_text(profile.get("company"))
            blog_host = urllib.parse.urlparse(str(profile.get("blog") or "")).netloc.lower().removeprefix("www.")
            evidence: list[str] = []
            if expected_base and profile_name and profile_name == expected_base:
                evidence.append("exact_profile_name")
            if expected_base and profile_company and profile_company == expected_base:
                evidence.append("company_field")
            if blog_host and any(blog_host == domain or blog_host.endswith("." + domain) for domain in domains):
                evidence.append("confirmed_domain")
            strong_match = "confirmed_domain" in evidence or {
                "exact_profile_name", "company_field"
            }.issubset(evidence)
            if not strong_match:
                continue
            verified.append(
                {
                    "login": profile.get("login"),
                    "url": profile.get("html_url"),
                    "name": profile.get("name"),
                    "blog": profile.get("blog"),
                    "evidence": evidence,
                }
            )
    if verified:
        for org in verified:
            print(f"  {G}[+] {org['login']} - {org['url']} ({', '.join(org['evidence'])}){W}")
    else:
        print("  -> Nenhuma organização pôde ser confirmada por nome exato, campo empresa ou domínio oficial.")
    return verified


def consultar_entidade_rdap(cnpj: str, timeout: float = 10) -> dict | None:
    print(f"\n{C}[!] REGISTRO.BR RDAP (entidade por documento; sem inferir domínios){W}")
    url = f"https://rdap.registro.br/entity/{cnpj}"
    data = make_http_request(url, timeout=timeout)
    if not isinstance(data, dict):
        print("  -> Entidade RDAP não retornada.")
        return None
    handle = str(data.get("handle") or "")
    if handle and only_digits(handle) != cnpj:
        print(f"  {Y}[!] Resposta descartada: handle não corresponde exatamente ao CNPJ.{W}")
        return None
    print(f"  {G}[+] Entidade RDAP confirmada pelo CNPJ exato.{W}")
    return {
        "handle": handle,
        "status": data.get("status", []),
        "remarks": data.get("remarks", []),
        "source_url": url,
        "match_method": "document_exact",
    }


def analyze_dns(domain: str) -> dict:
    print(f"\n{C}[!] DNS PASSIVO: {domain}{W}")
    output: dict[str, list[str]] = {}
    for record_type in ("A", "AAAA", "MX", "TXT", "NS"):
        result = run_cmd(["dig", "+short", record_type, domain])
        values = [line.strip() for line in (result or "").splitlines() if line.strip()]
        output[record_type] = values
        if values:
            print(f"  [{record_type}]")
            for value in values:
                print(f"    -> {value}")
    return output


def certificate_names(domain: str, timeout: float = 12) -> list[str]:
    print(f"\n{C}[!] CERTIFICATE TRANSPARENCY: {domain}{W}")
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    data = make_http_request(url, timeout=timeout)
    names: set[str] = set()
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in str(entry.get("name_value") or "").splitlines():
                name = name.strip().lower().rstrip(".")
                if name and "*" not in name and (name == domain or name.endswith("." + domain)):
                    names.add(name)
    for name in sorted(names)[:20]:
        print(f"     -> {name}")
    if not names:
        print("  -> Nenhum nome de certificado retornado.")
    print(f"  {Y}[i] Certificado demonstra emissão histórica; não prova que o host esteja ativo ou pertença hoje à empresa.{W}")
    return sorted(names)


def analyze_geoint(data: dict) -> dict:
    print(f"\n{C}[!] ENDEREÇO CADASTRAL E MAPA{W}")
    full_address = (
        f"{data.get('logradouro', '')}, {data.get('numero', '')} {data.get('complemento', '')} - "
        f"{data.get('bairro', '')}, {data.get('municipio', '')}/{data.get('uf', '')} - CEP {data.get('cep', '')}"
    ).strip()
    print(f"  Endereço cadastral: {full_address}")
    tokens = ["sala", "andar", "cond", "edificio", "ed.", "bloco", "suite", "coworking"]
    signals = sorted({token for token in tokens if token in full_address.lower()})
    if signals:
        print(f"  {Y}[i] Termos de imóvel compartilhado/comercial: {', '.join(signals)}. Sinal não conclusivo.{W}")
    query = urllib.parse.quote(
        f"{data.get('logradouro', '')}, {data.get('numero', '')}, {data.get('municipio', '')} - {data.get('uf', '')}, Brasil"
    )
    map_url = f"https://www.openstreetmap.org/search?query={query}"
    print(f"  -> OpenStreetMap: {map_url}")
    return {"address": full_address, "signals": signals, "classification": "not_inferred", "map_url": map_url}


def document_metadata_module(company_name: str, cnpj: str) -> dict:
    print(f"\n{C}[!] METADADOS DE DOCUMENTOS (módulo local){W}")
    available = bool(run_cmd(["which", "exiftool"]))
    query = f'filetype:pdf "{cnpj}" "{company_name}"'
    print(f"  Pesquisa sugerida: {query}")
    if available:
        print(f"  {G}[+] ExifTool disponível. Nenhum documento alheio é baixado automaticamente.{W}")
    else:
        print(f"  {Y}[i] ExifTool não encontrado.{W}")
    return {"exiftool_available": available, "search_query": query, "automatic_download": False}


def safe_dorks(company_name: str, cnpj: str, domain: str | None = None) -> list[str]:
    print(f"\n{C}[!] PESQUISAS ABERTAS COM IDENTIFICADOR EXATO{W}")
    dorks = [
        f'filetype:pdf "{cnpj}"',
        f'site:in.gov.br "{cnpj}"',
        f'site:pncp.gov.br "{cnpj}"',
        f'site:tcu.gov.br "{cnpj}"',
        f'site:gov.br "{cnpj}" "{company_name}"',
    ]
    if domain:
        dorks.append(f'"{cnpj}" "{domain}"')
    for query in dorks:
        print(f"    -> {query}")
    return dorks


def build_company_graph(data: dict, domains: list[str], github_orgs: list[dict], output_path: Path) -> None:
    company_name = str(data.get("razao_social") or "Empresa").replace('"', "'")
    cnpj = str(data.get("cnpj") or "")
    lines = ["graph TD", f'    CNPJ["{company_name}<br/>{cnpj}"]']
    for index, partner in enumerate((data.get("qsa") or [])[:10]):
        if not isinstance(partner, dict):
            continue
        name = str(partner.get("nome_socio") or "Sócio").replace('"', "'")
        node = f"Partner_{index}"
        lines.append(f'    {node}["{name}"]')
        lines.append(f"    CNPJ -->|QSA da fonte cadastral| {node}")
    for index, domain in enumerate(domains):
        node = f"Domain_{index}"
        lines.append(f'    {node}["{domain}"]')
        lines.append(f"    CNPJ -->|e-mail cadastral| {node}")
    for index, org in enumerate(github_orgs):
        node = f"Github_{index}"
        lines.append(f'    {node}["GitHub: {org["login"]}"]')
        lines.append(f"    CNPJ -->|evidência verificada| {node}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def canonical_from_rfb(result: dict, cnpj: str) -> dict | None:
    if result.get("status") != "match" or not result.get("records"):
        return None
    bundle = result["records"][0]
    if not isinstance(bundle, dict):
        return None
    company = bundle.get("empresa") or {}
    establishment = bundle.get("estabelecimento") or {}
    partners = bundle.get("socios") or []
    if not isinstance(company, dict) or not isinstance(establishment, dict):
        return None
    return {
        "cnpj": cnpj,
        "razao_social": company.get("razao_social", ""),
        "nome_fantasia": establishment.get("nome_fantasia", ""),
        "descricao_situacao_cadastral": establishment.get("situacao_cadastral", ""),
        "data_situacao_cadastral": establishment.get("data_situacao_cadastral", ""),
        "data_inicio_atividade": establishment.get("data_inicio_atividade", ""),
        "natureza_juridica": company.get("natureza_juridica", ""),
        "capital_social": float(str(company.get("capital_social") or "0").replace(",", ".")),
        "porte": company.get("porte_empresa", ""),
        "email": establishment.get("email", ""),
        "ddd_telefone_1": f"{establishment.get('ddd1', '')}{establishment.get('telefone1', '')}",
        "ddd_telefone_2": f"{establishment.get('ddd2', '')}{establishment.get('telefone2', '')}",
        "logradouro": f"{establishment.get('tipo_logradouro', '')} {establishment.get('logradouro', '')}".strip(),
        "numero": establishment.get("numero", ""),
        "complemento": establishment.get("complemento", ""),
        "bairro": establishment.get("bairro", ""),
        "municipio": establishment.get("municipio", ""),
        "uf": establishment.get("uf", ""),
        "cep": establishment.get("cep", ""),
        "cnae_fiscal": establishment.get("cnae_principal", ""),
        "cnaes_secundarios": [
            {"codigo": code.strip(), "descricao": ""}
            for code in str(establishment.get("cnaes_secundarios") or "").split(",") if code.strip()
        ],
        "qsa": [
            {
                "nome_socio": partner.get("nome_socio"),
                "qualificacao_socio": partner.get("qualificacao_socio"),
                "data_entrada_sociedade": partner.get("data_entrada"),
                "identificador_socio": partner.get("identificador_socio"),
                "cpf_cnpj_socio_publicado": partner.get("cpf_cnpj_socio"),
                "faixa_etaria": partner.get("faixa_etaria"),
            }
            for partner in partners if isinstance(partner, dict)
        ],
        "_lupa_provenance": {
            "source": "Receita Federal - índice local", "match_method": "document_exact",
            "queried_at": utc_now(),
        },
    }


def cnpj_api_results(data: dict | None) -> list[dict]:
    if not data:
        return []
    raw_records = data.get("_lupa_source_records") or {}
    health = {item.get("source"): item for item in data.get("_lupa_api_health", [])}
    results: list[dict] = []
    urls = {
        "BrasilAPI": "https://brasilapi.com.br/docs#tag/CNPJ",
        "MinhaReceita": "https://minhareceita.org/",
        "CNPJ.ws": "https://publica.cnpj.ws/",
    }
    for source in ("BrasilAPI", "MinhaReceita", "CNPJ.ws"):
        item = health.get(source, {})
        if source in raw_records:
            results.append(
                result_base(
                    "cnpj_api_" + normalize_header(source), source, urls[source], "match",
                    records=[raw_records[source]], latency_ms=item.get("latency_ms"),
                )
            )
        else:
            results.append(
                result_base(
                    "cnpj_api_" + normalize_header(source), source, urls[source],
                    "error" if item.get("status") == "error" else "no_match",
                    error=item.get("error"), latency_ms=item.get("latency_ms"),
                )
            )
    return results


def run_cnpj(args: argparse.Namespace, cnpj: str) -> int:
    if not validate_cnpj(cnpj):
        print(f"{R}[-] CNPJ inválido: quantidade, repetição ou dígitos verificadores incorretos.{W}")
        return 2
    banner("CNPJ")
    print(f"{G}[✓] CNPJ validado: {format_cnpj(cnpj)}{W}")
    data: dict | None = None
    source: str | None = None
    results: list[dict] = []
    if not args.no_network:
        data, source = consultar_cnpj_multi_api(cnpj, timeout=args.timeout)
        results.extend(cnpj_api_results(data))

    jobs: list[tuple[str, object]] = []
    if not args.skip_rfb:
        jobs.append(("rfb_cnpj_completo", lambda: query_rfb_index(cnpj, args.cache_dir)))
    if not args.skip_pncp:
        jobs.append(("pncp_contratos", lambda: query_pncp_index(cnpj, args.cache_dir)))
    if not args.no_network:
        if not args.skip_tcu:
            jobs.append(("tcu_certidoes_cnpj", lambda: query_tcu_cnpj(cnpj, args.timeout)))
        if not args.skip_compras:
            jobs.append(("compras_fornecedor", lambda: query_compras_supplier(cnpj, "cnpj", args.timeout)))
        if not args.skip_cvm:
            jobs.append(("cvm_cia_aberta", lambda: query_cvm_cnpj(cnpj, args.cache_dir, args.timeout, args.refresh_cache)))
        if not args.skip_bcb:
            jobs.append(("bcb_entidades", lambda: query_bcb_cnpj(cnpj, args.timeout)))
        if not args.skip_cgu:
            for source_id, config in CGU_SOURCES.items():
                if "cnpj" not in config.get("document_types", []):
                    continue
                jobs.append(
                    (
                        source_id,
                        lambda sid=source_id: query_cgu(
                            sid, cnpj, args.cache_dir, args.timeout, args.refresh_cache
                        ),
                    )
                )

    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(jobs))) as executor:
            futures = {
                executor.submit(timed_call, callable_job): source_id
                for source_id, callable_job in jobs
            }
            for future in concurrent.futures.as_completed(futures):
                source_id = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = result_base(source_id, source_id, "", "error", error=str(exc))
                results.append(result)
                status = result.get("status")
                if status == "match":
                    print(f"  {G}[+] {result['source_name']}: {len(result.get('records', []))} registro(s){W}")
                elif status == "no_match":
                    print(f"  [=] {result['source_name']}: nenhum registro exato")
                elif status == "not_configured":
                    print(f"  {Y}[i] {result['source_name']}: índice/chave ainda não configurado{W}")
                else:
                    print(f"  {Y}[!] {result['source_name']}: {result.get('error', status)}{W}")

    rfb_result = next((item for item in results if item.get("source_id") == "rfb_cnpj_completo"), {})
    if not data:
        data = canonical_from_rfb(rfb_result, cnpj)
        source = "Receita Federal - índice local" if data else None
    if not data:
        print(f"{R}[-] Nenhuma fonte cadastral retornou o CNPJ exato.{W}")
        return 1

    print(f"\n{C}[!] DADOS PRINCIPAIS (Fonte: {source}; documento exato){W}")
    print(f"  Razão Social : {data.get('razao_social', '')}")
    print(f"  Fantasia     : {data.get('nome_fantasia', '')}")
    print(f"  CNPJ         : {data.get('cnpj', cnpj)}")
    print(f"  Status       : {data.get('descricao_situacao_cadastral', '')}")
    print(f"  Natureza Jur.: {data.get('natureza_juridica', '')}")
    capital = data.get("capital_social", 0)
    if isinstance(capital, (int, float)):
        print((f"  Capital Soc. : R$ {capital:,.2f}").replace(",", "X").replace(".", ",").replace("X", "."))

    print(f"\n{C}[!] ATIVIDADES ECONÔMICAS{W}")
    print(f"  CNAE principal: {data.get('cnae_fiscal', '')} - {data.get('cnae_fiscal_descricao', '')}")
    for item in data.get("cnaes_secundarios", []) or []:
        if isinstance(item, dict):
            print(f"    -> {item.get('codigo', '')} - {item.get('descricao', '')}")

    print(f"\n{C}[!] CONTATO CADASTRAL{W}")
    email = str(data.get("email") or "")
    print(f"  E-mail     : {email}")
    print(f"  Telefone(s): {data.get('ddd_telefone_1', '')} / {data.get('ddd_telefone_2', '')}")

    qsa = data.get("qsa", []) or []
    print(f"\n{C}[!] QUADRO SOCIETÁRIO (QSA - {len(qsa)} registro(s)){W}")
    for partner in qsa:
        if not isinstance(partner, dict):
            continue
        print(
            f"  -> {partner.get('nome_socio', '')} | {partner.get('qualificacao_socio', '')} | "
            f"faixa etária: {partner.get('faixa_etaria', 'N/I')}"
        )
    print(f"  {Y}[i] Associação reversa por nome foi removida: homônimos não são vínculo confiável.{W}")

    geoint = analyze_geoint(data)
    rdap = consultar_entidade_rdap(cnpj, timeout=args.timeout)
    confirmed_domains: list[str] = []
    if "@" in email:
        domain = email.rsplit("@", 1)[1].lower().strip()
        free_mail = {
            "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "uol.com.br", "bol.com.br",
        }
        if domain and domain not in free_mail:
            confirmed_domains.append(domain)

    dns: dict[str, dict] = {}
    certificates: dict[str, list[str]] = {}
    wayback: dict[str, list[dict]] = {}
    for domain in confirmed_domains[:3]:
        dns[domain] = analyze_dns(domain)
        certificates[domain] = certificate_names(domain, timeout=args.timeout)
        wayback[domain] = buscar_historico_wayback(domain, timeout=args.timeout)

    github_orgs = verified_github_orgs(
        str(data.get("razao_social") or ""), confirmed_domains, timeout=args.timeout
    )
    metadata = document_metadata_module(str(data.get("razao_social") or ""), cnpj)
    dorks = safe_dorks(
        str(data.get("razao_social") or ""),
        cnpj,
        confirmed_domains[0] if confirmed_domains else None,
    )

    evidence = {
        "matching_policy": "document_exact_or_confirmed_cadastral_field",
        "rejected_relations": ["partner_name_only", "github_first_name", "rdap_handle_as_domain"],
        "confirmed_domains_from_cadastral_email": confirmed_domains,
        "rdap_entity": rdap,
        "dns": dns,
        "certificate_transparency": certificates,
        "wayback": wayback,
        "github_organizations": github_orgs,
        "geoint": geoint,
        "document_metadata": metadata,
        "search_queries": dorks,
    }

    data["_lupa_evidence"] = evidence
    # Os registros brutos das três APIs já aparecem em `sources`; evita duplicação no canônico.
    data.pop("_lupa_source_records", None)
    results = deduplicate_records(results)
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "LUPA", "version": VERSION},
        "report_id": secrets.token_hex(8),
        "generated_at": utc_now(),
        "target": {"type": "CNPJ", "document": format_cnpj(cnpj), "checksum_valid": True},
        "matching_policy": {
            "accepted": ["document_exact", "official_exact_document_filter", "cnpj_root_exact", "confirmed_cadastral_field"],
            "rejected": ["name_only", "fuzzy_name", "first_name", "unverified_search_result", "masked_document_partial"],
        },
        "summary": {
            "matched_sources": sum(1 for item in results if item.get("status") == "match"),
            "matched_records": sum(len(item.get("records", [])) for item in results if item.get("status") == "match"),
            "source_statuses": source_status_summary(results),
            "divergent_fields": sorted((data.get("_lupa_consensus") or {}).get("divergences", {})),
            "absence_is_not_clearance_certificate": True,
        },
        "canonical": data,
        "sources": sorted(results, key=lambda item: str(item.get("source_id"))),
        "evidence_cascade": evidence,
    }
    save_history(report, cnpj, args.cache_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"dossie_{cnpj}.json"
    graph_path = args.output_dir / f"dossie_{cnpj}_grafo.mmd"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    build_company_graph(data, confirmed_domains, github_orgs, graph_path)
    print(f"\n{G}[+] Dossiê JSON: {json_path.resolve()}{W}")
    print(f"{G}[+] Grafo Mermaid: {graph_path.resolve()}{W}")
    print(f"{G}[✓] LUPA CNPJ concluída com política anti-falso positivo.{W}\n")
    return 0


def source_catalog() -> None:
    print("Fontes automáticas do modo CPF:")
    for source_id, config in TCU_SOURCES.items():
        print(f"  {source_id}: {config['name']} (webservice público, POST por CPF exato)")
    for source_id, config in CGU_SOURCES.items():
        if "cpf" not in config.get("document_types", ["cpf"]):
            continue
        if config.get("exact_document_available", True):
            detail = "download aberto, comparação local exata"
        else:
            detail = "API oficial com chave gratuita; download aberto mascara CPF"
        print(f"  {source_id}: {config['name']} ({detail})")
    print("  compras_fornecedor: Compras.gov.br (fornecedor por CPF exato)")
    print("  pncp_contratos: PNCP (índice incremental local por CPF exato/HMAC)")
    print("  tse_candidatos_<ano>: TSE Candidaturas (download aberto; pode bloquear automação por CDN)")
    print("Fonte manual:")
    print("  receita_cpf: Receita Federal (data de nascimento e validação humana)")
    print("\nFontes automáticas do modo CNPJ:")
    print("  BrasilAPI + MinhaReceita + CNPJ.ws: coleta simultânea, consenso e divergências")
    print("  rfb_cnpj_completo: índice local dos dados abertos completos da Receita Federal")
    print("  tcu_certidoes_cnpj: TCU/APF (consulta consolidada exata)")
    print("  compras_fornecedor: Compras.gov.br (fornecedor exato)")
    print("  cgu_ceis + cgu_cnep + cgu_cepim: sanções/impedimentos por CNPJ exato")
    print("  cvm_cia_aberta: cadastro diário de companhias abertas")
    print("  bcb_entidades: entidades supervisionadas por raiz CNPJ explicitamente rotulada")
    print("  pncp_contratos: índice incremental local de contratos e subcontratos")
    print("  Registro.br RDAP, DNS, Certificate Transparency, Wayback e GitHub verificado")
    print("\nNenhuma fonte de vazamentos, broker de dados ou API paga é usada.")


def health_check(args: argparse.Namespace) -> int:
    probes = [
        ("BrasilAPI", "https://brasilapi.com.br/api/cnpj/v1/00000000000191", "application/json"),
        ("MinhaReceita", "https://minhareceita.org/00000000000191", "application/json"),
        ("CNPJ.ws", "https://publica.cnpj.ws/cnpj/00000000000191", "application/json"),
        ("TCU/APF", f"{TCU_CNPJ_API}/00000000000191?seEmitirPDF=false", "application/json"),
        ("Compras.gov.br", f"{COMPRAS_API}?pagina=1&tamanhoPagina=10&cnpj=00000000000191&ativo=true", "application/json"),
        ("CVM", CVM_DATASET, "*/*"),
        ("Banco Central", f"{BCB_ODATA}/", "application/json"),
        ("PNCP", "https://pncp.gov.br/api/consulta/v3/api-docs", "application/json"),
        ("CGU", "https://portaldatransparencia.gov.br/download-de-dados/ceis", "text/html"),
    ]
    failures = 0
    output: list[dict] = []
    print(f"{C}Saúde das fontes públicas:{W}")
    for name, url, accept in probes:
        started = time.monotonic()
        raw, error = http_bytes(
            url, timeout=args.timeout, accept=accept, max_bytes=3 * 1024 * 1024
        )
        latency = round((time.monotonic() - started) * 1000)
        status = "ok" if raw is not None and not error else "error"
        failures += int(status == "error")
        output.append({"source": name, "status": status, "latency_ms": latency, "error": error})
        print(f"  {'[+]' if status == 'ok' else '[!]'} {name}: {status} ({latency} ms){' - ' + error if error else ''}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = args.output_dir / "lupa_source_health.json"
    path.write_text(json.dumps({"generated_at": utc_now(), "sources": output}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{G}[+] Relatório: {path.resolve()}{W}")
    return 0 if failures == 0 else 1


def parse_tse_years(raw: str | None) -> list[int]:
    if not raw:
        return default_tse_years()
    years: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not re.fullmatch(r"20\d{2}", item):
            raise argparse.ArgumentTypeError(f"ano TSE inválido: {item}")
        year = int(item)
        if year not in years:
            years.append(year)
    return years


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LUPA v7.0 - OSINT passivo, verificável e multibase por CNPJ ou CPF",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("documento", nargs="?", help="CPF (11 dígitos) ou CNPJ (14 dígitos)")
    parser.add_argument("--tipo", choices=["auto", "cpf", "cnpj"], default="auto", help="Tipo do documento")
    parser.add_argument("-p", "--passive", action="store_true", help="Compatibilidade: a LUPA opera apenas em modo passivo")
    parser.add_argument("--ack-lawful-use", action="store_true", help="Confirma finalidade legítima/base legal para consulta automatizada de CPF")
    parser.add_argument("--no-network", action="store_true", help="Valida o documento sem consultar a rede")
    parser.add_argument("--skip-tcu", action="store_true", help="Não consulta webservices públicos do TCU")
    parser.add_argument("--skip-cgu", action="store_true", help="Não baixa/consulta bases abertas da CGU")
    parser.add_argument("--skip-tse", action="store_true", help="Não tenta consultar datasets de candidaturas do TSE")
    parser.add_argument("--skip-compras", action="store_true", help="Não consulta fornecedores do Compras.gov.br")
    parser.add_argument("--skip-pncp", action="store_true", help="Não consulta o índice local do PNCP")
    parser.add_argument("--skip-rfb", action="store_true", help="Não consulta o índice completo local da Receita Federal")
    parser.add_argument("--skip-cvm", action="store_true", help="Não consulta o cadastro da CVM")
    parser.add_argument("--skip-bcb", action="store_true", help="Não consulta entidades supervisionadas do Banco Central")
    parser.add_argument("--tse-years", metavar="ANOS", help="Anos do TSE separados por vírgula, ex.: 2024,2022")
    parser.add_argument("--refresh-cache", action="store_true", help="Baixa novamente os datasets oficiais")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(os.environ.get("LUPA_CACHE_DIR", Path.home() / ".cache" / "lupa")),
        help="Cache local de bases públicas",
    )
    parser.add_argument("--output-dir", type=Path, default=Path.cwd(), help="Diretório dos relatórios")
    parser.add_argument("--timeout", type=float, default=15, help="Timeout HTTP por requisição, em segundos")
    parser.add_argument("--list-sources", action="store_true", help="Lista fontes e encerra")
    parser.add_argument("--health-check", action="store_true", help="Testa disponibilidade/latência das fontes sem usar CPF")
    parser.add_argument("--build-rfb-index", type=Path, metavar="DIRETORIO", help="Constrói índice local a partir dos ZIPs oficiais da Receita Federal")
    parser.add_argument("--sync-pncp-days", type=int, metavar="N", help="Sincroniza contratos do PNCP dos últimos N dias no índice local")
    parser.add_argument("--no-color", action="store_true", help="Desativa cores ANSI")
    parser.add_argument("--version", action="version", version=f"LUPA {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        disable_colors()
    if args.list_sources:
        source_catalog()
        return 0
    if args.health_check:
        return health_check(args)
    if args.build_rfb_index:
        return build_rfb_index(args.build_rfb_index, args.cache_dir)
    if args.sync_pncp_days is not None:
        return sync_pncp(args.sync_pncp_days, args.cache_dir, args.timeout)
    if not args.documento:
        parser.error(
            "informe um CPF/CNPJ ou use --list-sources, --health-check, "
            "--build-rfb-index ou --sync-pncp-days"
        )
    try:
        args.tse_years = parse_tse_years(args.tse_years)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    if args.timeout <= 0 or args.timeout > 120:
        parser.error("--timeout deve estar entre 0 e 120 segundos")

    document = only_digits(args.documento)
    document_type = args.tipo
    if document_type == "auto":
        document_type = "cpf" if len(document) == 11 else "cnpj" if len(document) == 14 else "unknown"
    if document_type == "cpf":
        return run_cpf(args, document)
    if document_type == "cnpj":
        return run_cnpj(args, document)
    print(f"{R}[-] Documento deve conter 11 dígitos (CPF) ou 14 dígitos (CNPJ).{W}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
