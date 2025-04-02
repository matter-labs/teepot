#!/usr/bin/env bash

#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Matter Labs
#

set -ex

BASE_DIR=${0%/*}

NO=${NO:-1}

ZONE=${ZONE:-us-central1-c}

nix build -L .#tdx_google

gsutil cp result/tdx_base_1.vmdk gs://tdx_vms/

gcloud migration vms image-imports create \
         --location=us-central1 \
         --target-project=tdx-pilot \
         --project=tdx-pilot \
         --skip-os-adaptation \
         --source-file=gs://tdx_vms/tdx_base_1.vmdk \
         tdx-img-pre-"${NO}"

gcloud compute instances stop tdx-pilot --zone ${ZONE} --project tdx-pilot || :
gcloud compute instances delete tdx-pilot --zone ${ZONE} --project tdx-pilot || :

while gcloud migration vms image-imports list --location=us-central1 --project=tdx-pilot | grep -F RUNNING; do
    sleep 1
done

gcloud compute images create \
         --project tdx-pilot \
         --guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE \
         --storage-location=us-central1 \
         --source-image=tdx-img-pre-"${NO}" \
         tdx-img-f-"${NO}"

gcloud compute instances create tdx-pilot \
         --machine-type c3-standard-4 --zone ${ZONE} \
         --confidential-compute-type=TDX \
         --maintenance-policy=TERMINATE \
         --image-project=tdx-pilot \
         --project tdx-pilot \
         --metadata=container_hub="docker.io",container_image="ghcr.io/matter-labs/test-tdx:117p5y281limw0w7b03v802ij00c5gzw" \
         --metadata-from-file=container_config=$BASE_DIR/config.json \
         --image tdx-img-f-"${NO}"
