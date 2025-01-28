/*------------------------------------------------------------------------------
 Copyright 2024 BSH Hausgeraete GmbH

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its
 contributors may be used to endorse or promote products derived from this
 software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 -----------------------------------------------------------------------------*/
#ifndef _BSHDBUS_NETDEV_H
#define _BSHDBUS_NETDEV_H

#include <linux/netdevice.h>
#include <linux/bshdbus.h>

/**
 * struct bshdbus_ops - BSH D-Bus netdevice operations
 * @set_addr_filter: function to set the address filter for message reception
 * @set_baud_rate: function to set the baud rate of the device
 *
 * These operations must be implemented by hardware specific BSH D-Bus drivers.
 */
struct bshdbus_ops {
	int (*set_addr_filter)(struct net_device *net_dev, u8 addr);
	int (*set_baud_rate)(struct net_device *net_dev, u32 baud_rate);
};

/**
 * struct bshdbus_priv - private BSH D-Bus netdevice data
 * @net_dev: pointer to netdevice
 * @ops: pointer to BSH D-Bus netdevice operations
 * @tx_ind_skb_max: maximum numer of transmit indications
 * @tx_ind_skb: pointer to array of sk_buffs for transmit indications
 */
struct bshdbus_priv {
	struct net_device *net_dev;
	struct bshdbus_ops *ops;
	unsigned int tx_ind_skb_max;
	struct sk_buff **tx_ind_skb;
};

/**
 * bshdbus_alloc_netdev - allocate a BSH D-Bus specific netdevice
 * @priv_size: size of the private data
 * @tx_ind_max: maximum number of transmit indication frames
 *
 * The allocated netdevice is named 'bshdbusX', with X as the interface number.
 *
 * Reserves memory for the transmit indications and for the driver specific
 * private data.
 *
 * Return:
 *  netdevice on success
 *  NULL on failure
 */
struct net_device *bshdbus_alloc_netdev(int priv_size, unsigned int tx_ind_max);

/**
 * bshdbus_free_netdev - free a BSH D-Bus specific netdevice
 * @net_dev: netdevice to free
 */
void bshdbus_free_netdev(struct net_device *net_dev);

/**
 * bshdbus_open_netdev - common open function for BSH D-Bus netdevice
 * @net_dev: netdevice to open
 *
 * This function should be called in the open function of the device driver.
 *
 * Return:
 *  0 on success
 */
int bshdbus_open_netdev(struct net_device *net_dev);

/**
 * bshdbus_close_netdev - common close function for BSH D-Bus netdevice
 * @net_dev: netdevice to close
 *
 * This function should be called in the close function of the device driver.
 */
void bshdbus_close_netdev(struct net_device *net_dev);

/**
 * bshdbus_register_netdev - register a BSH D-Bus netdevice
 * @net_dev: netdevice to register
 * @ops: BSH D-Bus specific device operations
 *
 * This function should be called to register a BSH D-Bus netdevice.
 *
 * Return:
 *  0 on success
 */
int bshdbus_register_netdev(struct net_device *net_dev,
		struct bshdbus_ops *ops);

/**
 * bshdbus_unregister_netdev - unregister a BSH D-Bus netdevice
 * @net_dev: netdevice to unregister
 *
 * This function should be called to unregister a BSH D-Bus netdevice.
 */
void bshdbus_unregister_netdev(struct net_device *net_dev);

#endif /* !_BSHDBUS_NETDEV_H */
