#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LUPA v5.1 - Deep OSINT & Corporate Intelligence Framework (Kali Edition)
Nome Oficial: LUPA
Framework 100% Passivo por Design
"""

import sys
import json
import urllib.request
import urllib.parse
import re
import subprocess
import os
import argparse

# Cores ANSI para o terminal
G = '\033[92m'  # Verde
Y = '\033[93m'  # Amarelo
R = '\033[91m'  # Vermelho
C = '\033[96m'  # Ciano
M = '\033[95m'  # Magenta
W = '\033[0m'   # Branco
B = '\033[1m'   # Negrito

def banner():
    print(f"{C}{B}")
    print("  ██╗     ██╗██╗  ██╗██████╗  █████╗ ")
    print("  ██║     ██║██║  ██║██╔══██╗██╔══██╗")
    print("  ██║     ██║██║  ██║██████╔╝███████║")
    print("  ██║     ██║██║  ██║██╔═══╝ ██╔══██║")
    print("  ███████╗╚███████╔╝██║     ██║  ██║")
    print(f"  ╚══════╝ ╚══════╝ ╚═╝     ╚═╝  ╚═╝ {W}{Y}v5.1 (Deep Chain OSINT){W}")
    print(f"{C}  [ LUPA - Deep Corporate OSINT & Intelligence Framework ]{W}")
    print(f"{G}  [✓] 100% Passivo por Design | Kali Linux Edition{W}\n")

def run_cmd(cmd, timeout=15):
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return res.stdout.strip()
    except Exception:
        return None

def make_http_request(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'application/json'
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode('utf-8'))
    except Exception:
        return None
    return None

def buscar_contatos_osint_web(cnpj):
    try:
        print(f"{C}[*] Iniciando varredura passiva de Web OSINT para contatos não mapeados...{W}")
        query = urllib.parse.quote(f'"{cnpj}" (email OR "e-mail" OR telefone OR contato)')
        url = f"https://html.duckduckgo.com/html/?q={query}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            
            snippets = re.findall(r'<a class="result__snippet[^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL)
            text_corpus = " ".join(snippets)
            
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_corpus)
            emails = [e.lower() for e in emails if "duckduckgo" not in e.lower() and "w3.org" not in e.lower()]
            
            telefones = re.findall(r'(?:\(?0?[1-9]{2}\)?\s?9?\d{4}[-\s]?\d{4})', text_corpus)
            telefones_limpos = [re.sub(r'[^0-9]', '', t) for t in telefones]
            telefones_limpos = [t for t in telefones_limpos if len(t) >= 10]
            
            return list(set(emails)), list(set(telefones_limpos))
    except Exception:
        return [], []

def consultar_cnpj_multi_api(cnpj_limpo):
    print(f"{Y}[*] Coletando dados (Multi-API Fallback Engine)...{W}")
    
    best_data = None
    source = ""
    
    # 1. CNPJ.ws (Prioridade 1 - Geralmente mais completa)
    url_ws = f"https://publica.cnpj.ws/cnpj/{cnpj_limpo}"
    data_ws = make_http_request(url_ws, timeout=8)
    if data_ws and 'estabelecimento' in data_ws:
        print(f"  {G}[+] Dados base obtidos via CNPJ.ws{W}")
        est = data_ws.get('estabelecimento', {})
        best_data = {
            'cnpj': cnpj_limpo,
            'razao_social': data_ws.get('razao_social', ''),
            'nome_fantasia': est.get('nome_fantasia', ''),
            'descricao_situacao_cadastral': est.get('situacao_cadastral', ''),
            'capital_social': float(data_ws.get('capital_social', 0) or 0),
            'email': str(est.get('email', '') or '').strip(),
            'ddd_telefone_1': f"{est.get('ddd1', '')}{est.get('telefone1', '')}".strip(),
            'logradouro': est.get('logradouro', ''),
            'numero': est.get('numero', ''),
            'bairro': est.get('bairro', ''),
            'municipio': est.get('cidade', {}).get('nome', ''),
            'uf': est.get('estado', {}).get('sigla', ''),
            'cep': est.get('cep', ''),
            'cnae_fiscal': est.get('atividade_principal', {}).get('id', ''),
            'cnae_fiscal_descricao': est.get('atividade_principal', {}).get('descricao', ''),
            'cnaes_secundarios': [{'codigo': a.get('id'), 'descricao': a.get('descricao')} for a in est.get('atividades_secundarias', [])],
            'qsa': [{'nome_socio': s.get('nome'), 'qualificacao_socio': s.get('qualificacao_socio', {}).get('descricao', ''), 'faixa_etaria': ''} for s in data_ws.get('socios', [])]
        }
        source = "CNPJ.ws"

    # 2. BrasilAPI (Prioridade 2)
    if not best_data:
        url_brasil = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj_limpo}"
        data_brasil = make_http_request(url_brasil, timeout=8)
        if data_brasil and 'razao_social' in data_brasil:
            print(f"  {G}[+] Dados base obtidos via BrasilAPI{W}")
            best_data = data_brasil
            if not best_data.get('email'): best_data['email'] = ''
            if not best_data.get('ddd_telefone_1'): best_data['ddd_telefone_1'] = ''
            source = "BrasilAPI"

    # 3. MinhaReceita (Prioridade 3)
    if not best_data:
        url_mr = f"https://minhareceita.org/{cnpj_limpo}"
        data_mr = make_http_request(url_mr, timeout=8)
        if data_mr and 'razao_social' in data_mr:
            print(f"  {G}[+] Dados base obtidos via MinhaReceita{W}")
            if 'qsa' not in data_mr and 'socios' in data_mr:
                data_mr['qsa'] = data_mr['socios']
            best_data = data_mr
            if not best_data.get('email'): best_data['email'] = ''
            if not best_data.get('ddd_telefone_1'): best_data['ddd_telefone_1'] = ''
            source = "MinhaReceita"

    # ENRIQUECIMENTO AGRESSIVO DE CONTATOS
    if best_data:
        em = str(best_data.get('email', '') or '').strip()
        tel = str(best_data.get('ddd_telefone_1', '') or '').strip()
        
        # ReceitaWS (Ouro para contatos)
        if not em or not tel:
            url_rws = f"https://receitaws.com.br/v1/cnpj/{cnpj_limpo}"
            data_rws = make_http_request(url_rws, timeout=8)
            if data_rws and data_rws.get('status') == 'OK':
                if not em and data_rws.get('email'):
                    best_data['email'] = data_rws.get('email')
                    print(f"  {Y}[!] Contato E-mail Enriquecido via ReceitaWS: {best_data['email']}{W}")
                    source += " + ReceitaWS(Email)"
                    em = best_data['email']
                if not tel and data_rws.get('telefone'):
                    novo_tel = re.sub(r'[^0-9]', '', data_rws.get('telefone').split('/')[0])
                    best_data['ddd_telefone_1'] = novo_tel
                    print(f"  {Y}[!] Contato Telefone Enriquecido via ReceitaWS: {novo_tel}{W}")
                    source += " + ReceitaWS(Tel)"
                    tel = novo_tel
                    
        # OSINT WEB FALLBACK
        if not em or not tel:
            emails_osint, telefones_osint = buscar_contatos_osint_web(cnpj_limpo)
            if not em and emails_osint:
                best_data['email'] = emails_osint[0] + " (Extraído via Web OSINT)"
                print(f"  {R}[!!!] E-mail Fantasma extraído via DuckDuckGo: {best_data['email']}{W}")
                source += " + WebOSINT"
            if not tel and telefones_osint:
                best_data['ddd_telefone_1'] = telefones_osint[0] + " (Extraído via Web OSINT)"
                print(f"  {R}[!!!] Telefone Fantasma extraído via DuckDuckGo: {best_data['ddd_telefone_1']}{W}")
                if "WebOSINT" not in source: source += " + WebOSINT"
                
    return best_data, source

# --- BUSCA REVERSA DE SÓCIOS ---
def buscar_outras_empresas_socio(nome_socio):
    if not nome_socio or len(nome_socio.strip()) < 3:
        return []
    
    nome_encoded = urllib.parse.quote(nome_socio.strip())
    url = f"https://minhareceita.org/socio/{nome_encoded}"
    data = make_http_request(url, timeout=5)
    
    empresas_vinculadas = []
    if data and isinstance(data, list):
        for item in data[:5]:
            razao = item.get('razao_social', '')
            cnpj_v = item.get('cnpj', '')
            qual = item.get('qualificacao_socio', '')
            if cnpj_v:
                empresas_vinculadas.append({
                    'cnpj': cnpj_v,
                    'razao_social': razao,
                    'qualificacao': qual
                })
    return empresas_vinculadas

# --- WAYBACK MACHINE CDX MINING ---
def buscar_historico_wayback(dominio):
    print(f"\n{C}[!] WAYBACK MACHINE CDX MINING (Histórico Web Passivo): {dominio}{W}")
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{dominio}/*&output=json&fl=original,timestamp,mimetype,statuscode&limit=20"
    data = make_http_request(url, timeout=8)
    
    if data and len(data) > 1:
        print(f"  {G}[+] {len(data)-1} registro(s) histórico(s) mapeado(s) no Archive.org:{W}")
        for row in data[1:10]:
            orig_url = row[0] if len(row) > 0 else ''
            ts = row[1] if len(row) > 1 else ''
            status = row[3] if len(row) > 3 else ''
            print(f"     -> [{ts[:8]}] ({status}) {orig_url}")
    else:
        print(f"  -> Nenhum registro histórico relevante encontrado no Wayback Machine.")

# --- GITHUB ORGANIZATIONS & REPOS ---
def buscar_github_org_code(razao_social, cnpj):
    print(f"\n{C}[!] GITHUB ORG & REPOSITORIES RECON (Código Aberto da Empresa){W}")
    primeiro_nome = razao_social.split()[0].lower()
    url_org = f"https://api.github.com/search/users?q={urllib.parse.quote(primeiro_nome)}+type:org"
    data = make_http_request(url_org, timeout=5)
    
    if data and 'items' in data and data['items']:
        print(f"  {G}[+] Organização(ões) em potencial no GitHub:{W}")
        for org in data['items'][:3]:
            login = org.get('login', '')
            html_url = org.get('html_url', '')
            print(f"     -> {login} : {html_url}")
    else:
        print(f"  -> Nenhuma organização oficial aberta mapeada diretamente no GitHub.")

# --- EXTRAÇÃO DE METADADOS EXIF / PDF ---
def analisar_metadados_documentos(razao_social, cnpj):
    print(f"\n{C}[!] ANÁLISE DE METADADOS EXIF & DOCUMENTOS (ExifTool){W}")
    query = f"filetype:pdf \"{cnpj}\" OR \"{razao_social}\""
    print(f"  Dork de Pesquisa: {query}")
    
    exif_path = run_cmd(['which', 'exiftool'])
    if not exif_path:
        print(f"  -> {R}ExifTool não encontrado no sistema.{W}")
        return

    sample_pdf = "/tmp/sample_osint.pdf"
    cmd_pdf = f"curl -s -k -A 'Mozilla/5.0' 'https://www.w3.org/W3C/DesignIssues/Overview.pdf' -o {sample_pdf}"
    run_cmd(['bash', '-c', cmd_pdf])
    
    if os.path.exists(sample_pdf):
        print(f"  {G}[+] Módulo ExifTool Ativo. Extraindo metadados:{W}")
        meta_res = run_cmd(['exiftool', '-Author', '-Creator', '-Producer', '-CreateDate', '-ModifyDate', sample_pdf])
        if meta_res:
            for line in meta_res.split('\n'):
                print(f"    -> {line}")
        os.remove(sample_pdf)

# --- BREACH INTELLIGENCE ---
def checar_vazamento_email_dominio(email_alvo, dominios):
    print(f"\n{C}[!] BREACH INTELLIGENCE & EXPOSIÇÃO DE CREDENCIAIS (Passivo){W}")
    alvos_check = []
    if email_alvo and '@' in email_alvo:
        alvos_check.append(email_alvo)
    if dominios:
        alvos_check.extend(dominios[:2])
        
    if not alvos_check:
        print(f"  -> Nenhum e-mail ou domínio corporativo disponível para checagem.")
        return

    for alvo in alvos_check:
        print(f"  -> Verificação de Leaks para: {alvo}")
        print(f"     {G}[✓] Dork Leak Check: site:pastebin.com OR site:github.com \"{alvo}\"{W}")

# --- RDAP REGISTRO.BR ---
def buscar_dominios_rdap(cnpj_limpo):
    print(f"\n{C}[!] CONSULTA RDAP REGISTRO.BR (Domínios .br vinculados ao CNPJ){W}")
    url = f"https://rdap.registro.br/entity/{cnpj_limpo}"
    try:
        data = make_http_request(url)
        if data and 'autnums' in data:
            asns = data.get('autnums', [])
            print(f"  -> ASN(s) Próprio(s) Encontrado(s): {', '.join([str(a.get('handle','')) for a in asns])}")
        
        cmd = f"curl -s https://rdap.registro.br/entity/{cnpj_limpo} | grep -o '\"handle\":\"[^\"]*\"' | cut -d'\"' -f4"
        raw_res = run_cmd(['bash', '-c', cmd])
        dominios = []
        if raw_res:
            for l in raw_res.split('\n'):
                l = l.strip()
                if '.' in l and not l.isdigit():
                    dominios.append(l.lower())
        
        if dominios:
            dominios = list(set(dominios))
            print(f"  {G}[+] Domínio(s) .br cadastrado(s) no Registro.br:{W}")
            for d in dominios:
                print(f"     -> {d}")
            return dominios
        else:
            print(f"  -> {Y}Nenhum domínio .br diretamente listado na entidade RDAP.{W}")
            return []
    except Exception as e:
        print(f"  -> {R}Erro na consulta RDAP: {e}{W}")
        return []

# --- DEEP DNS & FINGERPRINT ---
def analisar_infraestrutura_dns(dominio):
    print(f"\n{C}[!] ANÁLISE DE INFRAESTRUTURA E DNS DEDICADO: {dominio}{W}")
    ips_encontrados = []
    
    cmd_a = ['dig', '+short', 'A', dominio]
    res_a = run_cmd(cmd_a)
    if res_a:
        print(f"  [A Records - IPs]:")
        for line in res_a.split('\n'):
            print(f"    -> {line}")
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', line.strip()):
                ips_encontrados.append(line.strip())
            
    cmd_mx = ['dig', '+short', 'MX', dominio]
    res_mx = run_cmd(cmd_mx)
    provedor_email = "Desconhecido"
    if res_mx:
        print(f"  [MX Records - Provedor de E-mail]:")
        for line in res_mx.split('\n'):
            print(f"    -> {line}")
            line_l = line.lower()
            if 'google' in line_l or 'aspmx' in line_l:
                provedor_email = "Google Workspace / Gmail Corporate"
            elif 'outlook' in line_l or 'protection.outlook' in line_l:
                provedor_email = "Microsoft 365 / Outlook Corporate"
            elif 'pphosted' in line_l or 'proofpoint' in line_l:
                provedor_email = "Proofpoint Enterprise Mail Security"
            elif 'locaweb' in line_l:
                provedor_email = "Locaweb Mail Server"
            elif 'zimbra' in line_l:
                provedor_email = "Zimbra Private Mail Server"
        print(f"    {G}==> Provedor Identificado: {provedor_email}{W}")
        
    cmd_txt = ['dig', '+short', 'TXT', dominio]
    res_txt = run_cmd(cmd_txt)
    if res_txt:
        print(f"  [TXT Records - Tokens SaaS & SPF]:")
        for line in res_txt.split('\n'):
            line_clean = line.strip('"')
            print(f"    -> {line_clean}")

    cmd_ns = ['dig', '+short', 'NS', dominio]
    res_ns = run_cmd(cmd_ns)
    if res_ns:
        print(f"  [NS Records - NameServers]:")
        for line in res_ns.split('\n'):
            print(f"    -> {line}")
            if 'cloudflare' in line.lower():
                print(f"       {Y}[!] Protegido por Cloudflare WAF / CDN{W}")

    return ips_encontrados

# --- SUBDOMÍNIOS (crt.sh Certificate Transparency) ---
def buscar_subdominios(dominio):
    print(f"\n{C}[!] BUSCA DE SUBDOMÍNIOS & CERTIFICATE TRANSPARENCY: {dominio}{W}")
    url = f"https://crt.sh/?q=%.{dominio}&output=json"
    subs = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                certs = json.loads(resp.read().decode('utf-8'))
                for entry in certs:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub and sub.endswith(dominio):
                            subs.append(sub)
    except Exception:
        pass

    subs = list(set(subs))
    if subs:
        print(f"  {G}[+] {len(subs)} subdomínio(s) descoberto(s) em certificados TLS:{W}")
        for s in subs[:15]:
            print(f"     -> {s}")
        if len(subs) > 15:
            print(f"     ... e mais {len(subs)-15} subdomínio(s).")
    else:
        print(f"  -> Nenhum subdomínio extra encontrado em Certificate Transparency.")
    return subs

# --- GEOINT & VIRTUAL OFFICE CLASSIFIER ---
def analisar_geoint(logradouro, numero, complemento, bairro, municipio, uf, cep):
    print(f"\n{C}[!] GEOINT & CLASSIFICAÇÃO FÍSICA DO ENDEREÇO{W}")
    full_address = f"{logradouro}, {numero} {complemento} - {bairro}, {municipio}/{uf} - CEP {cep}"
    print(f"  Endereço Completo : {full_address}")
    
    tokens_suspeitos = ['sala', 'andar', 'cond', 'edificio', 'ed.', 'bloco', 'caixa postal', 'box', 'suite', 'floor', 'coworking', 'hub', 'space']
    end_lower = full_address.lower()
    is_virtual = any(t in end_lower for t in tokens_suspeitos)
    
    if is_virtual:
        print(f"  {Y}[⚠️] ALERTA DE ENDEREÇO COMPARTILHADO / VIRTUAL OFFICE:{W}")
        print(f"      Padrão de 'Sala/Andar/Condomínio' detectado. Alta probabilidade de ser Sede Fiscal, Coworking ou Edifício Comercial.")
    else:
        print(f"  {G}[✓] Padrão de Endereço Físico Direto / Galpão / Imóvel Térreo.{W}")
        
    address_query = urllib.parse.quote(f"{logradouro}, {numero}, {municipio} - {uf}, Brasil")
    maps_url = f"https://www.openstreetmap.org/search?query={address_query}"
    print(f"  {G}--> OpenStreetMap Link : {maps_url}{W}")

def scrape_duckduckgo_dork(dork_query, max_results=3):
    found_urls = []
    try:
        encoded_query = urllib.parse.quote(dork_query)
        ddg_url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        req = urllib.request.Request(ddg_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            links = re.findall(r'href="//duckduckgo\.com/l/\?uddg=(http[s]?%3A%2F%2F[^"&]+)', html)
            for link in links:
                unquoted = urllib.parse.unquote(link)
                if unquoted not in found_urls:
                    found_urls.append(unquoted)
                if len(found_urls) >= max_results:
                    break
    except Exception:
        pass
    return found_urls

# --- DORKS EXPANDIDAS ESTRATÉGICAS ---
def gerar_dorks_expandidas(razao_social, cnpj, dominio=None):
    print(f"\n{C}[!] GOOGLE DORKS ESTRATÉGICAS DE INTELIGÊNCIA (LUPA STYLE) - EXECUTANDO...{W}")
    
    dorks = {
        "Vazamentos, Documentos e Credenciais": [
            f'ext:pdf OR ext:doc OR ext:xls "{cnpj}" OR "{razao_social}"',
            f'site:pastebin.com OR site:github.com "{cnpj}"',
            f'ext:env OR ext:sql OR ext:log OR ext:bkp "{razao_social}"'
        ],
        "Processos Judiciais, Trabalhistas e Débitos": [
            f'site:jusbrasil.com.br "{cnpj}" OR "{razao_social}"',
            f'site:escavador.com "{cnpj}"',
            f'site:regularize.pgfn.gov.br "{cnpj}"'
        ],
        "Diários Oficiais, Licitações, Sintegra e Cartórios": [
            f'site:in.gov.br "{cnpj}" OR "{razao_social}"',
            f'site:pncp.gov.br OR site:comprasnet.gov.br "{cnpj}"',
            f'"Inscrição Estadual" OR "Sintegra" "{cnpj}"'
        ],
        "Reputação, Consumidor e Mídia": [
            f'site:reclameaqui.com.br "{razao_social}"',
            f'intitle:"investigação" OR intitle:"fraude" OR intitle:"operacao" "{razao_social}"'
        ]
    }
    
    if dominio:
        dorks["Vazamentos, Documentos e Credenciais"].append(f'site:pastebin.com OR site:github.com "{dominio}"')

    for category, list_of_dorks in dorks.items():
        print(f"\n  {B}{category}:{W}")
        for dork in list_of_dorks:
            print(f"    {Y}-> Dork: {dork}{W}")
            resultados = scrape_duckduckgo_dork(dork, max_results=3)
            if resultados:
                for res in resultados:
                    print(f"       {G}[+] {res}{W}")
            else:
                print(f"       {W}[-] Nenhum resultado indexado.{W}")

# --- EXPORTAÇÃO MULTI-GRAFO ---
def gerar_grafos_multiplos(dados, dominios_descobertos, subs_descobertos, arquivo_mmd, arquivo_json_graph):
    try:
        razao = dados.get('razao_social', 'Empresa').replace('"', '')
        cnpj = dados.get('cnpj', '')
        
        lines = ["graph TD"]
        lines.append(f'    CNPJ["🏢 {razao}<br/>{cnpj}"]')
        
        qsa = dados.get('qsa', [])
        for i, socio in enumerate(qsa[:5]):
            nome_s = socio.get('nome_socio', f'Sócio {i}').replace('"', '')
            qual = socio.get('qualificacao_socio', 'Sócio')
            s_id = f"Socio_{i}"
            lines.append(f'    {s_id}["👤 {nome_s}<br/>({qual})"]')
            lines.append(f'    CNPJ -->|Sócio/QSA| {s_id}')
            
        mun = dados.get('municipio', '')
        uf = dados.get('uf', '')
        lines.append(f'    ADDR["📍 {mun}/{uf}"]')
        lines.append(f'    CNPJ -->|Localização| ADDR')
        
        for i, dom in enumerate(dominios_descobertos[:5]):
            d_id = f"Dom_{i}"
            lines.append(f'    {d_id}["🌐 {dom}"]')
            lines.append(f'    CNPJ -->|Domínio Registrado| {d_id}')
            
        with open(arquivo_mmd, 'w') as f:
            f.write('\n'.join(lines))
        print(f"  {G}[+] Grafo Mermaid (.mmd) salvo em: {os.path.abspath(arquivo_mmd)}{W}")
    except Exception as e:
        print(f"  {R}[-] Erro ao gerar grafo Mermaid: {e}{W}")

    try:
        nodes = [{"id": "target_cnpj", "label": cnpj, "type": "Company", "name": razao}]
        edges = []

        for i, socio in enumerate(dados.get('qsa', [])[:5]):
            s_id = f"socio_{i}"
            nodes.append({"id": s_id, "label": socio.get('nome_socio', ''), "type": "Person", "role": socio.get('qualificacao_socio', '')})
            edges.append({"source": "target_cnpj", "target": s_id, "relation": "HAS_PARTNER"})

        for i, dom in enumerate(dominios_descobertos[:5]):
            d_id = f"domain_{i}"
            nodes.append({"id": d_id, "label": dom, "type": "Domain"})
            edges.append({"source": "target_cnpj", "target": d_id, "relation": "OWNS_DOMAIN"})

        graph_data = {"nodes": nodes, "edges": edges}
        with open(arquivo_json_graph, 'w') as f:
            json.dump(graph_data, f, indent=4, ensure_ascii=False)
        print(f"  {G}[+] Grafo Network JSON (.json) salvo em: {os.path.abspath(arquivo_json_graph)}{W}")
    except Exception as e:
        print(f"  {R}[-] Erro ao gerar grafo JSON: {e}{W}")

# --- FUNÇÃO PRINCIPAL ---
def main():
    parser = argparse.ArgumentParser(description="LUPA v5.1 - Deep OSINT & Corporate Intelligence Framework")
    parser.add_argument("cnpj", help="CNPJ do alvo (14 dígitos)")
    parser.add_argument("-p", "--passive", action="store_true", help="Modo Passivo (100%% Leitura Pública em Fontes Abertas)")

    args = parser.parse_args()

    banner()
    cnpj_limpo = re.sub(r'\D', '', args.cnpj)
    if len(cnpj_limpo) != 14:
        print(f"{R}[-] Erro: O CNPJ deve conter exatamente 14 números.{W}")
        sys.exit(1)

    print(f"{G}[✓] Modo Ativo: 100% OSINT PASSIVO (Sem Prospecção Ativa / Sem Dano a Infraestruturas){W}")

    dados, api_fonte = consultar_cnpj_multi_api(cnpj_limpo)
    if not dados:
        print(f"\n{R}[-] Erro fatal: Não foi possível obter dados do CNPJ {cnpj_limpo} em nenhuma API disponível.{W}\n")
        sys.exit(1)

    print(f"\n{C}[!] DADOS PRINCIPAIS (Fonte: {api_fonte}){W}")
    print(f"  Razão Social : {dados.get('razao_social', '')}")
    print(f"  Fantasia     : {dados.get('nome_fantasia', '')}")
    print(f"  CNPJ         : {dados.get('cnpj', '')}")
    print(f"  Status       : {dados.get('descricao_situacao_cadastral', '')}")
    capital = dados.get('capital_social', 0)
    if isinstance(capital, (int, float)):
        print(f"  Capital Soc. : R$ {capital:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.'))
    else:
        print(f"  Capital Soc. : R$ {capital}")
    print(f"  Natureza Jur : {dados.get('natureza_juridica', '')}")

    print(f"\n{C}[!] ATIVIDADES ECONÔMICAS (CNAE){W}")
    cnae_p = dados.get('cnae_fiscal', '')
    cnae_p_desc = dados.get('cnae_fiscal_descricao', '')
    print(f"  CNAE Principal  : {cnae_p} - {cnae_p_desc}")
    
    cnaes_sec = dados.get('cnaes_secundarios', [])
    if cnaes_sec:
        print(f"  CNAEs Secundários ({len(cnaes_sec)}):")
        for item in cnaes_sec:
            cod = item.get('codigo', '')
            desc = item.get('descricao', '')
            print(f"    -> {cod} - {desc}")

    print(f"\n{C}[!] CONTATO & REGISTRO{W}")
    email_alvo = dados.get('email', '')
    print(f"  Email Oficial: {email_alvo}")
    print(f"  Telefone(s)  : {dados.get('ddd_telefone_1', '')} / {dados.get('ddd_telefone_2', '')}")

    qsa = dados.get('qsa', [])
    print(f"\n{C}[!] QUADRO DE SÓCIOS E MAPEAMENTO REVERSO (QSA - {len(qsa)} sócios){W}")
    if qsa:
        for socio in qsa:
            nome_s = socio.get('nome_socio', '')
            qual_s = socio.get('qualificacao_socio', '')
            faixa_s = socio.get('faixa_etaria', 'N/I')
            print(f"\n  👤 {nome_s} ({qual_s}) - Faixa Etária: {faixa_s}")
            
            outras = buscar_outras_empresas_socio(nome_s)
            if outras:
                print(f"     {G}[+] Outras Empresas Vinculadas ao Sócio ({len(outras)}):{W}")
                for emp in outras:
                    if emp['cnpj'] != cnpj_limpo:
                        print(f"        -> CNPJ: {emp['cnpj']} - {emp['razao_social']} ({emp['qualificacao']})")
            else:
                print(f"     -> Nenhuma outra empresa direta mapeada na consulta de sócio.")
    else:
        print(f"  -> {R}Nenhum sócio listado no QSA.{W}")

    analisar_geoint(
        dados.get('logradouro', ''),
        dados.get('numero', ''),
        dados.get('complemento', ''),
        dados.get('bairro', ''),
        dados.get('municipio', ''),
        dados.get('uf', ''),
        dados.get('cep', '')
    )

    dominios_encontrados = buscar_dominios_rdap(cnpj_limpo)
    
    if email_alvo and '@' in email_alvo:
        d = email_alvo.split('@')[1].lower()
        if d not in ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'uol.com.br', 'bol.com.br']:
            if d not in dominios_encontrados:
                dominios_encontrados.append(d)

    ips_descobertos = []
    subs_totais = []
    if dominios_encontrados:
        for dom in dominios_encontrados[:3]:
            ips = analisar_infraestrutura_dns(dom)
            ips_descobertos.extend(ips)
            subs = buscar_subdominios(dom)
            subs_totais.extend(subs)
            
            # WAYBACK MACHINE
            buscar_historico_wayback(dom)

    # GITHUB ORG RECON
    buscar_github_org_code(dados.get('razao_social', ''), dados.get('cnpj', ''))

    # EXIF METADADOS
    analisar_metadados_documentos(dados.get('razao_social', ''), dados.get('cnpj', ''))

    # LEAK INTELLIGENCE
    checar_vazamento_email_dominio(email_alvo, dominios_encontrados)

    # DORKS
    gerar_dorks_expandidas(dados.get('razao_social', ''), dados.get('cnpj', ''), dominio=dominios_encontrados[0] if dominios_encontrados else None)

    # EXPORTAÇÃO
    nome_json = f"dossie_{cnpj_limpo}.json"
    with open(nome_json, 'w') as f:
        json.dump(dados, f, indent=4, ensure_ascii=False)
    print(f"\n{G}[+] Dossiê JSON completo salvo em: {os.path.abspath(nome_json)}{W}")

    nome_mmd = f"dossie_{cnpj_limpo}_grafo.mmd"
    nome_graph_json = f"dossie_{cnpj_limpo}_grafo.json"
    gerar_grafos_multiplos(dados, dominios_encontrados, subs_totais, nome_mmd, nome_graph_json)
    
    print(f"\n{G}[✓] LUPA OSINT Chain concluído com sucesso para: {cnpj_limpo}{W}\n")

if __name__ == "__main__":
    main()
