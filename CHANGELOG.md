# Changelog

## 7.1.0 — 2026-09-04

- ReceitaWS restaurada como quarta fonte cadastral gratuita, sempre com validação
  do CNPJ devolvido e respeito ao limite público de três consultas por minuto;
- telefones da companhia e do responsável de RI da base diária oficial da CVM
  passam a ser preservados com a respectiva proveniência;
- consulta RDAP pelo domínio exato com descoberta do servidor autoritativo pela
  IANA, vínculo registrante–CNPJ e papéis de contato estruturados;
- fallback WHOIS direto do Registro.br disponível por opção explícita para
  verificação técnica, administrativa ou legal;
- contatos RDAP/WHOIS nunca entram no arquivo destinado a vendedores;
- coleta conservadora no site corporativo verificado: `tel:`, `mailto:`, JSON-LD,
  metadados e páginas de contato, respeitando `robots.txt`, limite de páginas,
  mesmo domínio e proteção contra destinos de rede privada;
- novo `leads_<CNPJ>.json`, contendo apenas contatos comerciais filtrados,
  sinais de qualificação, proveniência, exigência de opt-out e alertas LGPD;
- domínios informados com `--domain` permanecem candidatos até confirmação por
  CNPJ/nome no site ou por titularidade RDAP exata.

## 7.0.0 — 2026-09-02

- modo CPF por documento exato, com proteção do identificador em relatórios e índices;
- consulta simultânea de BrasilAPI, MinhaReceita e CNPJ.ws, com consenso e divergências;
- conectores para TCU/APF, Compras.gov.br, CGU, CVM e Banco Central;
- índices locais para dados completos da Receita Federal e contratos do PNCP;
- deduplicação, histórico entre execuções, saúde e latência por fonte;
- remoção de associações por homônimo, buscas de vazamentos e inferências frágeis.

## 5.1 — histórico

- versão inicial do repositório, focada em CNPJ.
