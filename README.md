# LUPA v7.1

OSINT passivo, multibase e verificável por CNPJ e CPF.

A versão 7.1 preserva os módulos CNPJ da LUPA e o modo CPF real da versão 6,
ampliando a cobertura apenas com fontes públicas, oficiais ou abertas e
gratuitas. Um achado automático nunca é aceito somente por nome.

## Novidades da versão 7.1

- ReceitaWS voltou como quarta fonte cadastral gratuita. O CNPJ retornado é
  validado exatamente e o limite público de três consultas por minuto é
  respeitado; use `--skip-receitaws` para desativá-la.
- Os campos de telefone da companhia e do responsável de RI, já presentes no
  CSV diário da CVM, agora são preservados.
- Cada domínio candidato é consultado no RDAP autoritativo. Para domínios que
  não terminam em `.br`, o servidor correto é descoberto pelo bootstrap da IANA.
- A LUPA coleta `tel:`, `mailto:`, JSON-LD, metadados e até três páginas de
  contato do site corporativo, somente depois de confirmar o vínculo por CNPJ,
  nome empresarial/fantasia ou titular RDAP.
- Um arquivo separado `leads_<CNPJ>.json` leva aos vendedores apenas canais
  corporativos filtrados, com origem, data, método de vínculo, consenso e
  controles de oposição. Contatos pessoais aparentes e celulares isolados
  ficam retidos para revisão.
- Contatos de RDAP/WHOIS podem ser incluídos no dossiê com
  `--include-registry-contacts`, apenas para verificação técnica,
  administrativa ou legal. Eles nunca aparecem no arquivo comercial.

Também permanecem as melhorias da versão 7.0:

- As fontes cadastrais CNPJ são
  consultadas em paralelo. O relatório mantém cada resposta, cria consenso por
  campo e explicita divergências; não existe mais fallback que pare na primeira.
- TCU/APF por CNPJ exato, fornecedor do Compras.gov.br por CPF ou CNPJ exato,
  CVM por CNPJ exato, Banco Central por raiz CNPJ rotulada e CEPIM/CGU por CNPJ.
- CEAF e PEP podem ser consultadas por CPF com a chave gratuita oficial do
  Portal da Transparência. Sem a chave, aparecem como `not_configured`, nunca
  como “nada consta”.
- Índice SQLite da base completa da Receita Federal: empresa,
  estabelecimento exato, Simples/MEI, QSA e tabelas auxiliares.
- Índice incremental de contratos do PNCP, incluindo fornecedor e
  subcontratado. CPFs são indexados com HMAC local e não aparecem em nomes de
  arquivo nem em relatórios.
- Deduplicação, latência por fonte, estado individual (`match`, `no_match`,
  `error`, `not_configured`), histórico de snapshots e diferenças entre
  execuções.
- Cascata CNPJ conservadora: e-mail cadastral → domínio confirmado → DNS,
  certificados e Wayback; GitHub só é aceito com evidência combinada.
- Diagnóstico de saúde das fontes com `lupa --health-check`.

## Fontes

CPF automático:

- TCU: inabilitados, inidôneos, CADIRREG e possível implicação eleitoral;
- CGU: CEIS e CNEP por download aberto; CEAF e PEP via chave gratuita;
- TSE: candidaturas nos anos selecionados;
- Compras.gov.br: cadastro de fornecedor;
- PNCP: contratos previamente sincronizados no índice local.

CNPJ automático:

- BrasilAPI, MinhaReceita, CNPJ.ws e ReceitaWS;
- dados abertos completos da Receita Federal, quando o índice local existe;
- TCU/APF, Compras.gov.br, CGU (CEIS, CNEP e CEPIM), CVM — incluindo
  telefones publicados — e Banco Central;
- PNCP previamente sincronizado;
- RDAP autoritativo, site corporativo verificado, Registro.br/WHOIS opt-in,
  DNS, Certificate Transparency, Wayback e GitHub verificado.

A situação cadastral do CPF na Receita Federal continua manual, pois a página
oficial exige data de nascimento e validação humana. Nenhum CAPTCHA, login,
bloqueio ou limite é contornado.

## Política contra falsos positivos

- correspondência primária somente por CPF/CNPJ exato;
- a raiz CNPJ do Banco Central é uma relação separada (`cnpj_root_exact`), não
  se passa por correspondência do estabelecimento completo;
- nenhum sócio é ligado a outra empresa somente pelo nome;
- nenhum nome, primeiro nome, fragmento de CPF ou resultado de busca é tratado
  como identidade confirmada;
- certificados TLS e endereço cadastral são sinais contextuais, não prova de
  propriedade ou classificação;
- divergências entre fontes não são escondidas pelo valor canônico.

Não são usadas bases vazadas, credenciais, brokers de dados, APIs pagas ou
técnicas de contorno. Ausência de achado não equivale a certidão negativa.

## Instalação no Kali

O instalador não usa `sudo`, guarda backup recuperável da versão atual e roda
smoke tests antes de concluir:

```bash
git clone https://github.com/marcosoliva957t-hue/lupa.git
cd lupa
./verify.sh
./install.sh
```

Comandos principais:

```bash
lupa --version
lupa --list-sources
lupa --health-check
lupa <CNPJ>
lupa <CNPJ> --domain empresa.com.br
lupa <CNPJ> --domain empresa.com.br --include-registry-contacts
lupa <CPF>
```

`--domain` é repetível. Um domínio informado pelo operador não é aceito como
verdade: a página precisa publicar o CNPJ/nome exato ou o RDAP precisa devolver
o CNPJ exato do titular. A coleta do site respeita `robots.txt`, fica no mesmo
domínio, não envia formulários, não passa por login e consulta no máximo quatro
páginas por padrão (`--max-site-pages`).

No modo CPF interativo, confirme a finalidade legítima. Em automação já
autorizada, use `--ack-lawful-use`.

## Ativar a base completa da Receita Federal

Baixe os ZIPs oficiais do conjunto CNPJ em um diretório local e construa o
índice uma vez:

```bash
lupa --build-rfb-index /caminho/para/zips-da-receita
```

O processo pode levar horas e exigir dezenas de gigabytes, de acordo com a
competência baixada. A troca do banco é atômica: um índice antigo funcional só
é substituído quando a nova construção termina.

## Sincronizar contratos do PNCP

O endpoint público não oferece filtro por fornecedor. Por isso a LUPA baixa por
período e consulta localmente por identificador exato:

```bash
lupa --sync-pncp-days 30
lupa --sync-pncp-days 365
```

Dias que falharem são registrados em `failed_dates`; não são silenciosamente
tratados como cobertura completa.

## Chave gratuita do Portal da Transparência

Para CEAF e PEP por CPF exato:

```bash
export LUPA_TRANSPARENCIA_API_KEY='sua-chave-gratuita'
lupa CPF --ack-lawful-use
```

A chave não é gravada pela LUPA. O cadastro é feito no próprio Portal da
Transparência.

## Cache e relatórios

O padrão é `~/.cache/lupa`. Use `--cache-dir` para mudar. Cada relatório contém
proveniência, política de vínculo, registros por fonte, consenso, divergências,
latências e alterações desde o snapshot anterior.

No modo CNPJ são produzidas três visões:

- `dossie_<CNPJ>.json`: relatório técnico completo;
- `leads_<CNPJ>.json`: saída reduzida para vendedores, sem QSA e sem contatos
  de diretório de registro;
- `dossie_<CNPJ>_grafo.mmd`: relações confirmadas em Mermaid.

O arquivo comercial prefere caixas funcionais (`vendas@`, `comercial@`,
`contato@` etc.), telefones publicados no site oficial ou em base oficial e
contatos confirmados por mais de uma família de fonte. Isso reduz falsos
positivos, mas não substitui avaliação de base legal nem autoriza disparos em
massa.

## Contatos de registro e uso comercial

A política do Registro.br permite consultas individuais para finalidades de
contato técnico, administrativo ou legal e proíbe publicidade, reprodução e
obtenção em massa. Por isso, `--include-registry-contacts` guarda os campos
públicos de RDAP/WHOIS apenas dentro do dossiê, com papel e restrição explícitos.
O exportador de leads ignora essa fonte por construção.

Para prospecção, a LUPA usa os telefones/e-mails cadastrais da empresa, a CVM e
o próprio site corporativo verificado. E-mails gratuitos ou de aparência
pessoal e celulares cadastrais encontrados isoladamente não são entregues como
`seller_ready`.

Referências que orientam esta implementação:

- [layout oficial dos dados abertos do CNPJ](https://www.gov.br/receitafederal/dados/cnpj-metadados.pdf/@@download/file);
- [cadastro diário de companhias abertas da CVM](https://dados.cvm.gov.br/dataset/cia_aberta-cad);
- [documentação da API pública ReceitaWS](https://receitaws.com.br/api);
- [RDAP do Registro.br](https://registro.br/rdap/) e
  [bootstrap RDAP da IANA](https://data.iana.org/rdap/dns.json);
- [Organization](https://schema.org/Organization) e
  [ContactPoint](https://schema.org/ContactPoint) do Schema.org;
- [política de privacidade do Registro.br](https://registro.br/politica-de-privacidade/);
- [guia da ANPD sobre legítimo interesse](https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/guia_orientativo_hipoteses_legais_tratamento_de_dados_pessoais_legitimo_interesse).

## Verificação e desenvolvimento

O runtime usa somente a biblioteca padrão do Python. A suíte não consulta a
internet e pode ser executada com:

```bash
./verify.sh
```

O diagnóstico opcional das fontes reais é separado:

```bash
python3 lupa.py --health-check --no-color
```

## Escopo e responsabilidade

A LUPA amplia a cobertura das fontes implementadas, mas não promete “todos os
dados da internet”. Cobertura depende da disponibilidade, do período, do
escopo legal de publicação e da configuração de cada fonte. Use somente com
finalidade legítima, base legal aplicável e respeito à LGPD e aos termos das
fontes. Não use para assédio, discriminação, fraude ou acesso não autorizado.

O repositório não deve receber relatórios, caches, documentos consultados,
chaves de API ou bancos SQLite. O `.gitignore` cobre esses artefatos comuns.
