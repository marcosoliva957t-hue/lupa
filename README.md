# LUPA 5.1

Ferramenta de inteligência corporativa e OSINT passivo para consulta e análise
de CNPJ usando fontes públicas.

## Uso responsável

A LUPA foi desenhada para pesquisa passiva. Respeite a legislação, os termos
das fontes consultadas e os direitos de privacidade aplicáveis. Não use os
resultados para assédio, discriminação ou acesso não autorizado.

## Instalação no Kali Linux

```bash
git clone URL_DESTE_REPOSITORIO lupa
cd lupa
./install.sh
lupa --help
```

O instalador cria os comandos `lupa` e `osint-cnpj` em `~/.local/bin`, sem
exigir privilégios de administrador.

## Uso

```bash
lupa 00000000000000 --passive
```

Substitua o exemplo por um CNPJ válido. Os arquivos de relatório são gravados
no diretório atual.

## Dependências

O runtime Python usa somente a biblioteca padrão. Para todos os módulos
opcionais, instale no Kali:

```bash
sudo apt update
sudo apt install -y curl dnsutils libimage-exiftool-perl
```

## Compatibilidade

A string de ajuda do argumento `--passive` usa `100%%` internamente porque o
`argparse` trata `%` como marcador de formatação. Na interface ela aparece
normalmente como `100%`.

Credenciais, dados consultados, relatórios e caches não fazem parte deste
repositório.

