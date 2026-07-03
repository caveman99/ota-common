#!/usr/bin/env bash
# Set up the packager venv (first run) and execute the pytest suite.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip >/dev/null
    .venv/bin/pip install -r requirements.txt
fi

.venv/bin/python -c "import detools; print('detools', detools.__version__)"
.venv/bin/python -m pytest tests -q "$@"
