#!/usr/bin/env bash
# Builds hallpass and the hallpass-client compatibility package at one
# version, the second pinned to the first, into OUT.
#   .github/scripts/build-python.sh 1.2.3 dist
set -euo pipefail
v="$1"
out="$2"
echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.]+)?$' || { echo "bad version: $v"; exit 1; }
sed -i "s/^__version__ = .*/__version__ = \"$v\"/" hallpass-py/src/hallpass/_version.py
grep -q "^__version__ = \"$v\"$" hallpass-py/src/hallpass/_version.py
compat=hallpass-py/compat/hallpass-client/pyproject.toml
sed -i "s/^version = \"0.0.0\"$/version = \"$v\"/; s/hallpass==0.0.0/hallpass==$v/g; s/hallpass\[strands\]==0.0.0/hallpass[strands]==$v/g" "$compat"
grep -q "^version = \"$v\"$" "$compat"
grep -q "hallpass==$v" "$compat"
python -m pip install --quiet build
python -m build hallpass-py -o "$out"
python -m build hallpass-py/compat/hallpass-client -o "$out"
ls -l "$out"
