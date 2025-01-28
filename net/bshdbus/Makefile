# SPDX-License-Identifier: GPL-2.0
#
#  Makefile for the BSH bus network core.
#

ccflags-y += -g -DDEBUG

obj-$(CONFIG_BSHDBUS) += bshdbus.o
bshdbus-y := af_bshdbus.o

obj-$(CONFIG_BSHDBUS) += bshdbus_dbus2.o
bshdbus_dbus2-y := dbus2.o
