#!/bin/bash

# Ubuntu has recent kernel versions than Debian.
gcloud compute instances create bpf-kvm \
       --enable-nested-virtualization \
       --zone asia-northeast1-b \
       --min-cpu-platform "AUTOMATIC" \
       --machine-type n2-standard-4 \
       --image-project ubuntu-os-cloud \
       --image-family ubuntu-2404-lts-amd64 \
       --boot-disk-size 50 \
       --project alphaus-dashboard
