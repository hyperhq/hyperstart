#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

###########################
# test hyperstart from hyper

export HYPER_RUNTIME=/var/lib/hyper
sudo mkdir -p ${HYPER_RUNTIME}
sudo cp build/kernel ${HYPER_RUNTIME}/kernel
sudo cp build/hyper-initrd.img ${HYPER_RUNTIME}/hyper-initrd.img

mkdir -p ${GOPATH}/src/github.com/hyperhq
git clone https://github.com/hyperhq/hyperd.git ${GOPATH}/src/github.com/hyperhq/hyperd
cd ${GOPATH}/src/github.com/hyperhq/hyperd
./autogen.sh
./configure
make
hack/test-cmd.sh

