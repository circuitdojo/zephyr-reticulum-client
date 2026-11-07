#!/usr/bin/env bash
# Run Zephyr's twister with the "fork" multiprocessing start method.
#
# Python 3.14 changed the Linux default to "forkserver", which pickles the
# runner and fails in twister ("cannot pickle 'select.epoll' object"). The
# Zephyr Tools venv ships 3.14, so force "fork" until twister handles it.
# Arguments go straight to twister, e.g.:
#   ret-client/scripts/twister.sh -T ret-client/tests -p native_sim --inline-logs
set -euo pipefail

: "${ZEPHYR_BASE:=$(west topdir)/zephyr}"
export ZEPHYR_BASE

exec python3 - "$@" <<'PY'
import multiprocessing
import os
import runpy
import sys

multiprocessing.set_start_method("fork")
scripts = os.path.join(os.environ["ZEPHYR_BASE"], "scripts")
sys.path.insert(0, scripts)
sys.argv = ["twister"] + sys.argv[1:]
runpy.run_path(os.path.join(scripts, "twister"), run_name="__main__")
PY
