#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
python3 -m py_compile "${SCRIPT_DIR}/lupa.py"
python3 "${SCRIPT_DIR}/lupa.py" --help >/dev/null
bash -n "${SCRIPT_DIR}/install.sh"
printf 'LUPA: validação concluída.\n'

