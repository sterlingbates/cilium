#!/bin/bash -e

# ----------------------------
# Incomplete.
# Requires a /vmshared path to be mounted to the VM for copying the image off.
# ----------------------------

ARTIF_PATH=docker-na-public.artifactory.swg-devops.com/wcp-genctl-sandbox-docker-local/kopilot/cilium/cilium
TAG=ngdc-$(whoami)

SEPR="------------------------------------------------------"

echo $SEPR
echo "Building Cilium..."
echo $SEPR

workdir=$HOME/Documents/Projects/RIAS-INFRA/SourceCode/src/cilium
#mkdir -p $workdir 2>/dev/null

#cp Dockerfile $workdir/

# Set up Cilium locally
#cd $workdir
#[ ! -d cilium ] && git clone https://github.com/sterlingbates/cilium.git
#cd cilium
#branch=$(git rev-parse --abbrev-ref HEAD)
#[ "$branch" != "ngdc" ] && git checkout ngdc
#git pull origin ngdc

# Create the build container
#mv ../Dockerfile .
#docker buildx build -f Dockerfile -t cilium:localbuild .
if ! docker images | grep cilium | grep localbuild; then
    docker buildx build -f Dockerfile -t cilium:localbuild .
fi
#rm -f Dockerfile

# Build Cilium and the image
set -o pipefail
docker run -it \
    -v /var/run/docker.sock:/var/run/docker.sock \
    cilium:localbuild \
    bash -ce 'make build && make docker-cilium-image' \
    2>&1 \
    | tee build.log
rc=$?
set +o pipefail

if grep "is not shared" build.log; then
    echo "${workdir} cannot be mounted to the Docker container. On Mac systems this may need to be added as a shareable volume."
    exit $rc
fi
[ $rc -ne 0 ] && echo $SEPR && echo "Error occurred running the build" && exit $rc

# Retag Cilium and push to Artifactory
docker tag quay.io/cilium/cilium:latest ${ARTIF_PATH}:${TAG}
docker push ${ARTIF_PATH}:${TAG}

echo $SEPR
echo "Image: ${ARTIF_PATH}:${TAG}"
echo $SEPR

echo "Done."
echo $SEPR
