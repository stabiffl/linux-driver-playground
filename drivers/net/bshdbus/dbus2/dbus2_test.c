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
#include <linux/workqueue.h>
#include <linux/bshdbus/skb.h>
#include <linux/bshdbus/netdev.h>

MODULE_DESCRIPTION("BSH D-Bus-2 Test Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

#pragma GCC push_options
#pragma GCC optimize ("O0")

struct dbus2test_dev {
	struct bshdbus_priv bshdbus;
	struct net_device *net_dev;
	struct work_struct tx_ind_work;
	void *device_data;
};

struct dbus2test_priv {
	struct bshdbus_priv priv;	/* must be the first member */
	struct dbus2test_dev *test_dev;
};

static struct dbus2test_priv priv;

static void dbus2test_simulate_rx_msg(struct dbus2test_dev *test_dev)
{
	int ret;
	struct sk_buff *skb;
	struct bshdbus2_frame *dbus2_frame;

	skb = bshdbus_alloc_skb(test_dev->net_dev, htons(ETH_P_BSHDBUS2),
			sizeof(struct bshdbus2_frame), (void **)&dbus2_frame);
	if (!skb) {
		netdev_err(test_dev->net_dev, "Allocate skb failed: %d", ret);
		return;
	}

	dbus2_frame->addr = 0xA0;
	dbus2_frame->flags = 0;
	dbus2_frame->msg_id_high = 0xFC;
	dbus2_frame->msg_id_low = 0xB0;
	dbus2_frame->data_len = 2;
	dbus2_frame->data[0] = 0xAF;
	dbus2_frame->data[1] = 0xFE;

	ret = bshdbus_push_rx_skb(skb);
	if (ret) {
		netdev_err(test_dev->net_dev, "Push received message failed: %d", ret);
	}
}

static void dbus2test_simulate_rx_broadcast(struct dbus2test_dev *test_dev)
{
	int ret;
	struct sk_buff *skb;
	struct bshdbus2_frame *dbus2_frame;

	skb = bshdbus_alloc_skb(test_dev->net_dev, htons(ETH_P_BSHDBUS2),
			sizeof(struct bshdbus2_frame), (void **)&dbus2_frame);
	if (!skb) {
		netdev_err(test_dev->net_dev, "Allocate skb failed: %d", ret);
		return;
	}

	dbus2_frame->addr = 0x01;
	dbus2_frame->flags = 0;
	dbus2_frame->msg_id_high = 0xB0;
	dbus2_frame->msg_id_low = 0xAD;
	dbus2_frame->data_len = 1;
	dbus2_frame->data[0] = 0x12;

	ret = bshdbus_push_rx_skb(skb);
	if (ret) {
		netdev_err(test_dev->net_dev, "Push broadcast failed: %d", ret);
	}
}

static int dbus2test_open_netdev(struct net_device *net_dev)
{
	int ret;

	ret = bshdbus_open_netdev(net_dev);
	if (ret) {
		netdev_err(net_dev, "Failed to open dev: %d\n", ret);
		return ret;
	}

	netif_start_queue(net_dev);

	return 0;
}

static int dbus2test_close_netdev(struct net_device *net_dev)
{
	netif_stop_queue(net_dev);
	bshdbus_close_netdev(net_dev);

	return 0;
}

static netdev_tx_t dbus2test_start_xmit(struct sk_buff *skb, struct net_device *net_dev)
{
	int ret;
	struct dbus2test_dev *test_dev = netdev_priv(net_dev);

/*
	if (can_dev_dropped_skb(dev, skb))
		return NETDEV_TX_OK;

	mb = get_tx_head_mb(priv);
	prio = get_tx_head_prio(priv);
*/

	ret = bshdbus_put_tx_ind_skb(skb, net_dev, 0);
	if (ret) {
		netdev_err(net_dev, "Put TX indication failed: %d", ret);
		return NETDEV_TX_BUSY;
	}

	/* Don't allow to call this function again until send was finished */
	netif_stop_queue(net_dev);

	schedule_work(&test_dev->tx_ind_work);

	return NETDEV_TX_OK;
}

static void dbus2test_tx_ind_work(struct work_struct *work)
{
	int ret;
	struct dbus2test_dev *test_dev = container_of(work, struct dbus2test_dev,
			tx_ind_work);

	ret = bshdbus_push_tx_ind_skb(test_dev->net_dev, 0);
	if (ret) {
		netdev_err(test_dev->net_dev, "Get TX indication failed: %d", ret);
		return;
	}

	/* Simulate a received message */
	dbus2test_simulate_rx_msg(test_dev);

	/* Simulate a received broadcast message */
	dbus2test_simulate_rx_broadcast(test_dev);

	netif_start_queue(test_dev->net_dev);
}

static const struct net_device_ops dbus2test_netdev_ops = {
	.ndo_open = dbus2test_open_netdev,
	.ndo_stop = dbus2test_close_netdev,
	.ndo_start_xmit = dbus2test_start_xmit,
//	.ndo_change_mtu = can_change_mtu,
};

static struct dbus2test_dev *alloc_dbus2test_dev(void)
{
	struct net_device *net_dev;
	struct dbus2test_dev *test_dev = NULL;

	net_dev = bshdbus_alloc_netdev(sizeof(*test_dev), 1);
	if (!net_dev) {
		pr_err("Failed to allocate BSH bus device");
		goto out;
	}

	test_dev = netdev_priv(net_dev);
	if (!test_dev) {
		netdev_err(net_dev, "Failed to init netdev");
		goto out;
	}

	test_dev->net_dev = net_dev;
	test_dev->net_dev->netdev_ops = &dbus2test_netdev_ops;

out:
	return test_dev;
}

static void free_dbus2test_dev(struct net_device *net_dev)
{
	bshdbus_free_netdev(net_dev);
}

static int dbus2test_set_baud_rate(struct net_device *net_dev, u32 baud_rate)
{
	netdev_info(net_dev, "Set baud rate to %d\n", baud_rate);

	return 0;
}

static int dbus2test_set_addr_filter(struct net_device *net_dev, u8 addr)
{
	if ((addr & 0xF0) == 0) {
		netdev_err(net_dev, "Address is a broadcast address");
		return -EINVAL;
	}

	netdev_info(net_dev, "Set address filter to 0x%02x", addr);

	return 0;
}

static const struct bshdbus_ops dbus2test_ops = {
	.set_baud_rate = dbus2test_set_baud_rate,
	.set_addr_filter = dbus2test_set_addr_filter
};

static __init int dbus2test_init(void)
{
	int ret;
	struct dbus2test_dev *test_dev;

	test_dev = alloc_dbus2test_dev();
	if (!test_dev)
		return -ENOMEM;

	test_dev->device_data = &priv;
	priv.test_dev = test_dev;

	ret = bshdbus_register_netdev(test_dev->net_dev, &dbus2test_ops);
	if (ret) {
		netdev_err(test_dev->net_dev, "Register device failed: %d\n", ret);
		goto free_dbus2_dev;
	}

	INIT_WORK(&test_dev->tx_ind_work, dbus2test_tx_ind_work);

	netdev_info(test_dev->net_dev, "BSH D-Bus-2 test driver initialized");

	return ret;

free_dbus2_dev:
	free_dbus2test_dev(test_dev->net_dev);

	return ret;
}

static __exit void dbus2test_exit(void)
{
	if (priv.test_dev) {
		bshdbus_unregister_netdev(priv.test_dev->net_dev); // TODO priv macht so keinen Sinn
		free_dbus2test_dev(priv.test_dev->net_dev);
	}
}

#pragma GCC pop_options

module_init(dbus2test_init);
module_exit(dbus2test_exit);
