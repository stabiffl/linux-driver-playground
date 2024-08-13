/*------------------------------------------------------------------------------
 Copyright 2023 BSH Hausgeraete GmbH

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
#include <linux/bshdbus/dev.h>

MODULE_DESCRIPTION("BSH D-Bus device driver interface");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

static void bshdbus_setup(struct net_device *dev)
{
	dev->type = ARPHRD_BSHDBUS;
	dev->mtu = 256; //TODO
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 20;
	dev->flags = IFF_NOARP;
	dev->features = NETIF_F_HW_CSUM;
}

struct net_device *bshdbus_alloc_dev(int sizeof_priv, unsigned int echo_skb_max)
{
	int size;
	struct net_device *dev;
	struct bshdbus_priv *priv;

	size = ALIGN(sizeof_priv, NETDEV_ALIGN);

	dev = alloc_netdev_mqs(size, "bshdbus%d", NET_NAME_UNKNOWN, bshdbus_setup,
			1, 1);
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);
	priv->dev = dev;

	return dev;
}
EXPORT_SYMBOL_GPL(bshdbus_alloc_dev);

void bshdbus_free_dev(struct net_device *dev)
{
	free_netdev(dev);
}
EXPORT_SYMBOL_GPL(bshdbus_free_dev);
