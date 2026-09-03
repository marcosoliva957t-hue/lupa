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
