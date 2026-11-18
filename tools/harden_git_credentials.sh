#!/usr/bin/env bash
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
set -euo pipefail

CRED_FILE="${HOME}/.git-credentials"

if [ -f "${CRED_FILE}" ]; then
    echo "[SECURITY] Обнаружен файл открытых токенов ${CRED_FILE}. Выполняем безвозвратное затирание..."
    if command -v shred >/dev/null 2>&1; then
        shred -u -n 3 -z "${CRED_FILE}"
    else
        dd if=/dev/zero of="${CRED_FILE}" bs=4096 count=1 conv=notrunc status=none || true
        rm -f "${CRED_FILE}"
    fi
    echo "[OK] Файл ${CRED_FILE} уничтожен."
else
    echo "[OK] Открытый файл ${CRED_FILE} отсутствует."
fi

git config --global --unset-all credential.helper 2>/dev/null || true
git config --global credential.helper 'cache --timeout=3600'
echo "[OK] Git переведён на эфемерный RAM-кэш (TTL 3600 сек, 0 следов на SSD)."
