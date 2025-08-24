#!/bin/sh

# Local build only; environment specific.
DOCKER_BUILDKIT=0 docker build --rm -t vortex-agent .
DOCKER_BUILDKIT=0 docker tag vortex-agent asia-docker.pkg.dev/mobingi-main/asia-pub/vortex-agent:$1
DOCKER_BUILDKIT=0 docker push asia-docker.pkg.dev/mobingi-main/asia-pub/vortex-agent:$1
DOCKER_BUILDKIT=0 docker rmi $(docker images --filter "dangling=true" -q --no-trunc) -f
sed -i -e 's/image\:\ asia-docker.pkg.dev\/mobingi\-main\/asia\-pub\/vortex\-agent[\:@].*$/image\:\ asia-docker.pkg.dev\/mobingi\-main\/asia\-pub\/vortex\-agent\:'$1'/g' daemonset.yaml
