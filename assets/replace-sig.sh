#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# This script is used to replace the signature of a gramine docker image with a new one.
#
# Usage: ./replace-sig.sh <image> <new-signature-file> <old-signature-file>
# Example: ./replace-sig.sh tva tee-vault-admin.sig /app/tee-vault-admin.sig

DOCKERFILE="Dockerfile-tmp-$$"

trap 'rm -f $DOCKERFILE' EXIT

cat > "$DOCKERFILE" <<EOF
FROM $1
COPY $2 $3
EOF

docker build -f "$DOCKERFILE" -t "$1" .
