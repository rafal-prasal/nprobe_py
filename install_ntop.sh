#!/bin/bash

set -e

arch=`dpkg --print-architecture`

case $arch in
    arm64)
        #normally should be like this, but unfortunately does not work
        #wget https://packages.ntop.org/RaspberryPI/apt-ntop.deb 
        #dpkg -i apt-ntop.deb sudo apt-get update
        #apt-get install ntopng

        #workaround for missing packages
        wget --quiet https://packages.ntop.org/RaspberryPI/bullseye_pi/all/ntopng-data/ntopng-data_6.1.231231_all.deb
        wget --quiet https://packages.ntop.org/RaspberryPI/bullseye_pi/arm64/ntopng/ntopng_6.1.231231-22516_arm64.deb 
        apt install -y ./ntopng-data_6.1.231231_all.deb 
        apt install -y ./ntopng_6.1.231231-22516_arm64.deb
    ;;
    amd64)
        wget https://packages.ntop.org/apt-stable/bullseye/all/apt-ntop-stable.deb 
        apt install -y ./apt-ntop-stable.deb
        apt update
        apt install -y ntop
    ;;
esac

