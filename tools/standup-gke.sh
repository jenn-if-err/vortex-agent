#!/bin/bash

gcloud container clusters create bpf-vm \
       --workload-pool=alphaus-dashboard.svc.id.goog \
       --project=alphaus-dashboard \
       --zone=asia-northeast1-b \
       --machine-type=e2-standard-2 \
       --scopes=default \
       --enable-autoscaling \
       --enable-vertical-pod-autoscaling \
       --min-nodes=1 --max-nodes=4 \
       --maintenance-window=16:00 \
       --network=default \
       --subnetwork=default \
       --enable-ip-alias \
       --addons=HttpLoadBalancing \
       --release-channel=regular
