#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE="${SCRIPT_DIR}/lupa.py"
INSTALL_ROOT="${HOME}/.local/share/gladios-lupa"
LUPA_DIR="${INSTALL_ROOT}/lupa"
BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
DESKTOP_DIR="${HOME}/Desktop"
BACKUP_ROOT="${HOME}/.local/state/gladios-lupa-backups"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lupa-v7-verify.XXXXXX")"
PY_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/lupa-v7-pycache.XXXXXX")"

cleanup() {
  rm -rf -- "${VERIFY_DIR}" "${PY_CACHE}"
}
trap cleanup EXIT INT TERM

die() {
  printf 'ERRO: %s\n' "$*" >&2
  exit 1
}

[[ -f "${SOURCE}" ]] || die "Arquivo lupa.py não encontrado ao lado do instalador."
head -n 1 "${SOURCE}" | grep -q 'python' || die "O arquivo principal não é um script Python."

printf 'Validando o pacote LUPA v7...\n'
if [[ -f "${SCRIPT_DIR}/SHA256SUMS" ]] && command -v shasum >/dev/null 2>&1; then
  (cd "${SCRIPT_DIR}" && shasum -a 256 -c SHA256SUMS)
fi
PYTHONPYCACHEPREFIX="${PY_CACHE}" python3 -m py_compile "${SOURCE}"
python3 "${SOURCE}" --version | grep -Fq 'LUPA 7.1.0' || die "Versão inesperada."
python3 "${SOURCE}" --list-sources >/dev/null

mkdir -p "${LUPA_DIR}" "${BIN_DIR}" "${APP_DIR}" "${DESKTOP_DIR}" "${BACKUP_DIR}"

backup_index=0
for current in \
  "${LUPA_DIR}/osint-cnpj" \
  "${BIN_DIR}/lupa" \
  "${BIN_DIR}/osint-cnpj" \
  "${BIN_DIR}/lupa-gui" \
  "${APP_DIR}/lupa.desktop" \
  "${DESKTOP_DIR}/LUPA.desktop"; do
  if [[ -e "${current}" || -L "${current}" ]]; then
    backup_index=$((backup_index + 1))
    cp -pP -- "${current}" "${BACKUP_DIR}/${backup_index}-$(basename -- "${current}")"
  fi
done

install -m 0755 "${SOURCE}" "${LUPA_DIR}/osint-cnpj.new"
mv -f -- "${LUPA_DIR}/osint-cnpj.new" "${LUPA_DIR}/osint-cnpj"

cat >"${BIN_DIR}/lupa" <<EOF
#!/usr/bin/env bash
exec python3 "${LUPA_DIR}/osint-cnpj" "\$@"
EOF

cat >"${BIN_DIR}/osint-cnpj" <<EOF
#!/usr/bin/env bash
exec "${BIN_DIR}/lupa" "\$@"
EOF

cat >"${BIN_DIR}/lupa-gui" <<'EOF'
#!/usr/bin/env bash
set -u
mkdir -p "${HOME}/Documents/LUPA-Resultados"
cd "${HOME}/Documents/LUPA-Resultados" || exit 1
printf '\nLUPA v7 — OSINT passivo, multibase e verificável por CPF/CNPJ\n\n'
printf 'Digite o CPF ou CNPJ: '
IFS= read -r documento
[[ -n "${documento}" ]] || { printf 'Documento vazio.\n'; exit 2; }
"${HOME}/.local/bin/lupa" "${documento}" --passive
printf '\nRelatórios: %s\n' "${HOME}/Documents/LUPA-Resultados"
EOF

chmod 0755 "${BIN_DIR}/lupa" "${BIN_DIR}/osint-cnpj" "${BIN_DIR}/lupa-gui"

cat >"${APP_DIR}/lupa.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=LUPA v7
Comment=OSINT passivo, multibase e verificável por CPF ou CNPJ
Exec=xfce4-terminal --title=LUPA-v7 --hold --command=${BIN_DIR}/lupa-gui
Icon=system-search
Terminal=false
Categories=Utility;Security;
EOF

chmod 0755 "${APP_DIR}/lupa.desktop"
cp -p -- "${APP_DIR}/lupa.desktop" "${DESKTOP_DIR}/LUPA.desktop"
chmod 0755 "${DESKTOP_DIR}/LUPA.desktop"
if command -v gio >/dev/null 2>&1; then
  gio set "${DESKTOP_DIR}/LUPA.desktop" metadata::trusted true >/dev/null 2>&1 || true
fi

printf 'Executando smoke tests sem rede...\n'
FIXTURE_CPF="529982247""25"
FIXTURE_CPF_FORMATTED="529.982.247""-25"
"${BIN_DIR}/lupa" --version | grep -Fq 'LUPA 7.1.0'
"${BIN_DIR}/lupa" --list-sources | grep -Fq 'tcu_contas_irregulares'
"${BIN_DIR}/lupa" --list-sources | grep -Fq 'rfb_cnpj_completo'
"${BIN_DIR}/lupa" "${FIXTURE_CPF}" --no-network --no-color --output-dir "${VERIFY_DIR}" >/dev/null
test -n "$(find "${VERIFY_DIR}" -maxdepth 1 -name 'relatorio_cpf_final_*.json' -print -quit)"
if grep -Rqs -- "${FIXTURE_CPF}\|${FIXTURE_CPF_FORMATTED}" "${VERIFY_DIR}"; then
  die "O teste de privacidade encontrou CPF bruto no relatório."
fi

printf '\nLUPA v7 instalada e validada.\n'
printf 'Backup recuperável: %s\n' "${BACKUP_DIR}"
printf 'Comandos: lupa, osint-cnpj, lupa --list-sources\n'
printf 'Atalho: %s\n' "${DESKTOP_DIR}/LUPA.desktop"
