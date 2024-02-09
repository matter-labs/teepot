#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# This script is used to extract the signature of a gramine docker image.
#
# Usage: ./extract-sig.sh <image-name> <tee-name> <output-file>
# Example: ./extract-sig.sh tva tee-vault-admin

id=$(docker create $1)
trap 'docker rm -v $id' EXIT
docker cp "$id:/app/$2.sig" "$3"
