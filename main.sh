#!/bin/sh
# Author: Aaron Esau <python@aaronesau.com>
#
# This script just wraps smuggie so that you can test without installing
# smuggie via setup.py every time.

set -e

curdir="$(dirname "$(realpath "$0")")"
PYTHONPATH="${PYTHONPATH}:$curdir" "${curdir}/scripts/smuggie" "$@"
