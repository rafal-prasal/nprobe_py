#!/bin/bash

set -e

arch=`dpkg --print-architecture`

case $arch in
    arm64)
        #currently only in unstable channels
        channel=apt
        pkg=apt-ntop.deb
    ;;
    amd64)
        channel=apt-stable
        pkg=apt-ntop-stable.deb
    ;;
    *)
        echo unnknown architecture
        exit 1
    ;;
esac

wget https://packages.ntop.org/${channel}/bookworm/all/${pkg}
apt install -y ./${pkg}
apt update

apt install -y ntopng

