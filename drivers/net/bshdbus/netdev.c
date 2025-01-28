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
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/bshdbus/skb.h>
#include <linux/bshdbus/netdev.h>
#include <linux/bshdbus/bshdbus-ml.h>

MODULE_DESCRIPTION("BSH D-Bus Device Driver Interface");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

static void bshdbus_setup_netdev(struct net_device *net_dev)
{
	net_dev->type = ARPHRD_BSHDBUS;
	net_dev->mtu = BSHDBUS_MTU;
	net_dev->hard_header_len = 0;
	net_dev->addr_len = 0;
	net_dev->tx_queue_len = 20;
	net_dev->flags = IFF_NOARP;
	net_dev->features = NETIF_F_HW_CSUM;
}

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
struct net_device *bshdbus_alloc_netdev(int priv_size, unsigned int tx_ind_max)
{
	int size;
	struct net_device *net_dev;
	struct bshdbus_priv *priv;
	struct bshdbus_ml_priv *ml_priv;

	if (!tx_ind_max)
		return NULL;

	/*
	 * The memory layout for the netdev_priv is like this:
	 *
	 * +------------------------------------+
	 * | hardware specific driver's priv    |
	 * +------------------------------------+
	 * | struct bshdbus_ml_priv             |
	 * +------------------------------------+
	 * | array of struct sk_buff            |
	 * +------------------------------------+
	 */
	size = ALIGN(priv_size, NETDEV_ALIGN) + sizeof(struct bshdbus_ml_priv);
	size = ALIGN(size, sizeof(struct sk_buff *)) +
			tx_ind_max * sizeof(struct sk_buff *);

	net_dev = alloc_netdev_mqs(size, "bshdbus%d", NET_NAME_UNKNOWN,
			bshdbus_setup_netdev, 1, 1);
	if (!net_dev)
		return NULL;

	priv = netdev_priv(net_dev);
	priv->net_dev = net_dev;

	ml_priv = (void *)priv + ALIGN(priv_size, NETDEV_ALIGN);
	bshdbus_set_ml_priv(net_dev, ml_priv);

	priv->tx_ind_skb_max = tx_ind_max;
	priv->tx_ind_skb = (void *)priv +
			(size - tx_ind_max * sizeof(struct sk_buff *));

	return net_dev;
}
EXPORT_SYMBOL_GPL(bshdbus_alloc_netdev);


/**
 * bshdbus_free_netdev - free a BSH D-Bus specific netdevice
 * @net_dev: netdevice to free
 */
void bshdbus_free_netdev(struct net_device *net_dev)
{
	free_netdev(net_dev);
}
EXPORT_SYMBOL_GPL(bshdbus_free_netdev);

/**
 * bshdbus_open_netdev - common open function for BSH D-Bus netdevice
 * @net_dev: netdevice to open
 *
 * This function should be called in the open function of the device driver.
 *
 * Return:
 *  0 on success
 */
int bshdbus_open_netdev(struct net_device *net_dev)
{
	/* Switch carrier on if device was stopped while in bus-off state */
	if (!netif_carrier_ok(net_dev)) //TODO nochmal nachgehen
		netif_carrier_on(net_dev);

	return 0;
}
EXPORT_SYMBOL_GPL(bshdbus_open_netdev);

/**
 * bshdbus_close_netdev - common close function for BSH D-Bus netdevice
 * @net_dev: netdevice to close
 *
 * This function should be called in the close function of the device driver.
 */
void bshdbus_close_netdev(struct net_device *net_dev)
{
	struct bshdbus_priv *priv = netdev_priv(net_dev);

//	cancel_delayed_work_sync(&priv->restart_work); // TODO nötig?
	bshdbus_flush_tx_ind_skb(net_dev);
}
EXPORT_SYMBOL_GPL(bshdbus_close_netdev);

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
int bshdbus_register_netdev(struct net_device *net_dev, struct bshdbus_ops *ops)
{
	struct bshdbus_priv *priv = netdev_priv(net_dev);

	priv->ops = ops;
	netif_carrier_off(net_dev);

	return register_netdev(net_dev);
}
EXPORT_SYMBOL_GPL(bshdbus_register_netdev);

/**
 * bshdbus_unregister_netdev - unregister a BSH D-Bus netdevice
 * @net_dev: netdevice to unregister
 *
 * This function should be called to unregister a BSH D-Bus netdevice.
 */
void bshdbus_unregister_netdev(struct net_device *net_dev)
{
	unregister_netdev(net_dev);
}
EXPORT_SYMBOL_GPL(bshdbus_unregister_netdev);
