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
#include <linux/bshdbus/skb.h>
#include <linux/bshdbus/netdev.h>

MODULE_DESCRIPTION("BSH D-Bus Device Driver Interface");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

static void init_bshdbus_skb_reserve(struct sk_buff *skb)
{
	//skb->pkt_type = PACKET_BROADCAST;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	bshdbus_skb_reserve(skb);
}

static struct sk_buff *bshdbus2_create_tx_ind_skb(struct sk_buff *skb)
{
	struct sk_buff *new_skb;
	struct bshdbus2_frame *dbus2_frame = (struct bshdbus2_frame *)skb->data;

	new_skb = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(!new_skb)) {
		kfree_skb(skb);
		return NULL;
	}

	dbus2_frame->type = BSHDBUS_MSG_TYPE_TX_IND;

	bshdbus_skb_set_owner(new_skb, skb->sk);
	consume_skb(skb);

	return new_skb;
}

static void bshdbus2_set_rx_skb_properties(struct sk_buff *skb)
{
	struct bshdbus2_frame *dbus2_frame = (struct bshdbus2_frame *)skb->data;

	if (0x00 == (dbus2_frame->addr & 0xF0))
		skb->pkt_type = PACKET_BROADCAST;
	else
		skb->pkt_type = PACKET_USER;

	dbus2_frame->type = BSHDBUS_MSG_TYPE_RX;
}

/**
 * bshdbus_alloc_skb - allocate a BSH D-Bus specific sk_buff
 * @net_dev: pointer to netdevice
 * @protocol: BSH D-Bus Ethernet Protocol ID
 * @data_len: length of data
 * @data: returned pointer to allocated data
 *
 * This function should be used to create a BSH D-Bus specific sk_buff.
 *
 * Return:
 *  sk_buff on success
 *  NULL on failure
 */
struct sk_buff *bshdbus_alloc_skb(struct net_device *net_dev, __be16 protocol,
		unsigned int data_len, void **data)
{
	struct sk_buff *skb;

	if (unlikely(protocol != htons(ETH_P_BSHDBUS2))) {
		goto leave_with_error;
	}

	skb = netdev_alloc_skb(net_dev, sizeof(struct bshdbus_skb_priv) + data_len);
	if (unlikely(!skb)) {
		goto leave_with_error;
	}

	skb->protocol = protocol;
	init_bshdbus_skb_reserve(skb);
	bshdbus_skb_prv(skb)->ifindex = net_dev->ifindex;

	*data = skb_put_zero(skb, data_len);

	return skb;

leave_with_error:
	*data = NULL;
	return NULL;
}
EXPORT_SYMBOL_GPL(bshdbus_alloc_skb);

/**
 * bshdbus_push_rx_skb - push a BSH D-Bus sk_buff containing a received frame
 * @skb: pointer to sk_buff
 *
 * This function pushes a BSH D-Bus specific sk_buff, which contains a received
 * frame, to the transport layer.
 *
 * Return:
 *  0 on success
 *  -EINVAL when sk_buff is invalid
 *  -EPROTONOSUPPORT when sk_buff has no BSH D-Bus protocol set
 *  -ENOMSG when processing of the sk_buff fails
 */
int bshdbus_push_rx_skb(struct sk_buff *skb)
{
	int ret = 0;

	if (unlikely(!skb))
		return -EINVAL;

	if (unlikely(skb->protocol == htons(ETH_P_BSHDBUS2)))
		bshdbus2_set_rx_skb_properties(skb);
	else {
		ret = -EPROTONOSUPPORT;
		goto leave_with_error;
	}

	if (netif_rx(skb) != NET_RX_SUCCESS) {
		ret = -ENOMSG;
		goto leave_with_error;
	}

	return 0;

leave_with_error:
	dev_kfree_skb_any(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(bshdbus_push_rx_skb);

static struct sk_buff *
__bshdbus_push_tx_ind_skb(struct net_device *net_dev, unsigned int idx)
{
	struct sk_buff *skb = NULL;
	struct bshdbus_priv *priv = netdev_priv(net_dev);

	if (idx >= priv->tx_ind_skb_max) {
		netdev_err(net_dev, "%d exceeds TX indication array size %d",
			   idx, priv->tx_ind_skb_max);
		return NULL;
	}

	if (priv->tx_ind_skb[idx]) {
		skb = priv->tx_ind_skb[idx];
//		struct  bshdbus_skb_priv *can_skb_priv = can_skb_prv(skb);

		if (skb_shinfo(skb)->tx_flags & SKBTX_IN_PROGRESS)
			skb_tstamp_tx(skb, skb_hwtstamps(skb));

		/* get the real payload length for netdev statistics */
// TODO		*len_ptr = can_skb_get_data_len(skb);

		priv->tx_ind_skb[idx] = NULL;

		if (skb->pkt_type != PACKET_LOOPBACK) {
			dev_consume_skb_any(skb);
			return NULL;
		}
	}

	return skb;
}

/**
 * bshdbus_push_tx_ind_skb - push a BSH D-Bus transmit indication frame
 * @net_dev: pointer to netdevice
 * @idx: index of the transmit indication on the stack
 *
 * This function pushes a BSH D-Bus specific sk_buff, which contains a transmit
 * indication frame, to the transport layer.
 *
 * The function is typically called when the TX done interrupt is handled in the
 * device driver.
 *
 * Context: The device driver must protect access to priv->tx_ind_skb, if
 * necessary.
 *
 * Return:
 *  0 on success
 *  -ENODEV when netdevice is invalid
 *  -ENOMSG when sk_buff with the specified index does not exist
 *  -EPROTONOSUPPORT when sk_buff has no BSH D-Bus protocol set
 */
int bshdbus_push_tx_ind_skb(struct net_device *net_dev, unsigned int idx)
{
	int ret;
	struct sk_buff *skb;

	if (unlikely(!net_dev))
		return -ENODEV;

	skb = __bshdbus_push_tx_ind_skb(net_dev, idx);
	if (!skb)
		return -ENOMSG;

	skb_get(skb);

	if (skb->protocol != htons(ETH_P_BSHDBUS2)) {
		netdev_err(net_dev, "Invalid BSH D-Bus protocol for TX indication");
		ret = -EPROTONOSUPPORT;
		goto leave_with_error;
	}

	if (netif_rx(skb) == NET_RX_SUCCESS)
		dev_consume_skb_any(skb);
	else
		dev_kfree_skb_any(skb);

	return 0;

leave_with_error:
	dev_kfree_skb_any(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(bshdbus_push_tx_ind_skb);

/**
 * bshdbus_put_tx_ind_skb - put a BSH D-Bus transmit indication sk_buff on stack
 * @skb: pointer to sk_buff
 * @net_dev: pointer to netdevice
 * @idx: index of the transmit indication on the stack
 *
 * This function puts a transmit indication on the stack for later processing.
 * The function is typically called in the start_xmit function of the device
 * driver.
 *
 * Context: The device driver must protect access to priv->tx_ind_skb, if
 * necessary.
 *
 * Return:
 *  0 on success
 *  -EINVAL when index is invalid
 *  -ENOMEM when copy of sk_buff fails
 *  -EPROTONOSUPPORT when sk_buff has no BSH D-Bus protocol set
 *  -EBUSY when index is already occupied
 */
int bshdbus_put_tx_ind_skb(struct sk_buff *skb, struct net_device *net_dev,
                           unsigned int idx)
{
	struct bshdbus_priv *priv = netdev_priv(net_dev);

	if (idx >= priv->tx_ind_skb_max) {
		netdev_err(net_dev, "%d exceeds TX indication array size %d",
			   idx, priv->tx_ind_skb_max);
		return -EINVAL;
	}

	if (!priv->tx_ind_skb[idx]) {
		if (skb->protocol == htons(ETH_P_BSHDBUS2)) {
			skb = bshdbus2_create_tx_ind_skb(skb);
			if (!skb) {
				netdev_err(net_dev, "Allocate memory for TX indication failed");
				return -ENOMEM;
			}
		}
		else {
			netdev_err(net_dev, "Invalid BSH D-Bus protocol for TX indication");
			kfree_skb(skb);
			return -EPROTONOSUPPORT;
		}

		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->dev = net_dev;

		/* save frame_len to reuse it when transmission is completed */
/*		can_skb_prv(skb)->frame_len = frame_len; */

		if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

		skb_tx_timestamp(skb);

		/* save this skb for tx interrupt handling */
		priv->tx_ind_skb[idx] = skb;
	}
	else {
		netdev_err(net_dev, "TX indication %d already occupied", idx);
		kfree_skb(skb);
		return -EBUSY;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(bshdbus_put_tx_ind_skb);

/**
 * bshdbus_flush_tx_ind_skb - flush all transmit indications from the stack
 * @net_dev: pointer to netdevice
 *
 * This function flushes all transmit indications from the stack.
 *
 * Context: The device driver must protect access to priv->tx_ind_skb, if
 * necessary.
 */
void bshdbus_flush_tx_ind_skb(struct net_device *net_dev)
{
	struct bshdbus_priv *priv = netdev_priv(net_dev);
	struct net_device_stats *stats = &net_dev->stats;
	int i;

	for (i = 0; i < priv->tx_ind_skb_max; i++) {
		if (priv->tx_ind_skb[i]) {
			kfree_skb(priv->tx_ind_skb[i]);
			priv->tx_ind_skb[i] = NULL;
			stats->tx_dropped++;
			stats->tx_aborted_errors++;
		}
	}
}
