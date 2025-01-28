#!/bin/bash

set -e

ARCH=arm64 CROSS_COMPILE=/bin/aarch64-linux-gnu- make modules
sshfs -p 2222 pi@localhost:/ ~/dbuscan/modules
ARCH=arm64 CROSS_COMPILE=/bin/aarch64-linux-gnu- make modules_install INSTALL_MOD_PATH=/home/EU.BSHG.COM/birknerwo/dbuscan/modules
umount ~/dbuscan/modules
ARCH=arm64 CROSS_COMPILE=/bin/aarch64-linux-gnu- make modules_install INSTALL_MOD_PATH=/tmp/modules
ssh -p 2222 pi@localhost "sudo modprobe -r dbus2_test; sudo modprobe -r bshdbus-dbus2; sudo modprobe bshdbus-dbus2; sudo modprobe dbus2-test"
