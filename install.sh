#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_ROOT="${HOME}/.local/share/lupa"
BIN_DIR="${HOME}/.local/bin"

command -v python3 >/dev/null 2>&1 || {
  printf 'ERRO: python3 não encontrado.\n' >&2
  exit 1
}

mkdir -p "${INSTALL_ROOT}" "${BIN_DIR}"
install -m 0755 "${SCRIPT_DIR}/lupa.py" "${INSTALL_ROOT}/lupa.py"

cat >"${BIN_DIR}/lupa" <<EOF
#!/usr/bin/env bash
exec "$(command -v python3)" "${INSTALL_ROOT}/lupa.py" "\$@"
EOF

cat >"${BIN_DIR}/osint-cnpj" <<'EOF'
#!/usr/bin/env bash
exec "${HOME}/.local/bin/lupa" "$@"
EOF

chmod 0755 "${BIN_DIR}/lupa" "${BIN_DIR}/osint-cnpj"
"${BIN_DIR}/lupa" --help >/dev/null
printf 'LUPA instalada em %s\n' "${INSTALL_ROOT}"
printf 'Comandos: %s/lupa e %s/osint-cnpj\n' "${BIN_DIR}" "${BIN_DIR}"

