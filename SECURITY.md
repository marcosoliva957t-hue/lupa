# Segurança e privacidade

Não abra uma issue pública contendo CPF, CNPJ consultado, relatório, chave,
token, credencial ou outro dado pessoal. Compartilhe falhas de segurança em
canal privado com o responsável pelo repositório.

Antes de um commit, execute:

```bash
./verify.sh
git diff --cached
```

Relatórios, caches, bases baixadas e índices locais não pertencem ao Git. O
modo CPF mascara o documento exportado e usa HMAC com segredo local no índice
do PNCP; ainda assim, o operador deve controlar acesso ao computador e aos
resultados.

Contatos de RDAP/WHOIS só são incluídos com `--include-registry-contacts` e
pertencem exclusivamente ao dossiê de verificação. Eles não aparecem no arquivo
`leads_*.json`, não são elegíveis para prospecção e não devem ser redistribuídos.
O operador deve respeitar a finalidade técnica, administrativa ou legal e os
termos do registro responsável.

O arquivo comercial também não torna um contato automaticamente lícito para
uma campanha. A organização usuária continua responsável por definir a base
legal, documentar o teste de balanceamento quando aplicável, informar origem e
finalidade e manter lista efetiva de oposição/descadastramento.
