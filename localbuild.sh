#!/bin/sh

# Local build only; environment specific.
docker build --rm -t vortex-agent .
docker tag vortex-agent asia-docker.pkg.dev/mobingi-main/asia-pub/vortex-agent:$1
docker push asia-docker.pkg.dev/mobingi-main/asia-pub/vortex-agent:$1
docker rmi $(docker images --filter "dangling=true" -q --no-trunc) -f
sed -i -e 's/image\:\ asia-docker.pkg.dev\/mobingi\-main\/asia\-pub\/vortex\-agent[\:@].*$/image\:\ asia-docker.pkg.dev\/mobingi\-main\/asia\-pub\/vortex\-agent\:'$1'/g' daemonset.yaml
