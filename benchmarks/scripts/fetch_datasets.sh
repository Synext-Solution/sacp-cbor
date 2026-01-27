#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/datasets"

APPENDIX_URL="https://raw.githubusercontent.com/cbor/test-vectors/master/appendix_a.json"
APPENDIX_FILE="$DATA_DIR/appendix_a.json"
APPENDIX_SHA="80e78dc2f53cfdc9836094791d09e84c6818edf380f7cdd4be26a5c2dc4e9f3a"

mkdir -p "$DATA_DIR"

curl -L -o "$APPENDIX_FILE" "$APPENDIX_URL"

echo "$APPENDIX_SHA  $APPENDIX_FILE" | sha256sum -c -

echo "Datasets fetched."
