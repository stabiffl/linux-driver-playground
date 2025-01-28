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
#ifndef _BSHDBUS_SKB_H
#define _BSHDBUS_SKB_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/bshdbus.h>
#include <net/sock.h>

/*
void can_free_echo_skb(struct net_device *dev, unsigned int idx,
		       unsigned int *frame_len_ptr);
struct sk_buff *alloc_can_err_skb(struct net_device *dev,
				  struct can_frame **cf);
bool can_dropped_invalid_skb(struct net_device *dev, struct sk_buff *skb);
*/

/**
 * bshdbus_push_tx_ind_skb - push a BSH D-Bus transmit indication frame
 * @net_dev: pointer to netdevice
 * @idx: index of the transmit indication to push
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
int bshdbus_push_tx_ind_skb(struct net_device *net_dev, unsigned int idx);

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
                           unsigned int idx);

/**
 * bshdbus_flush_tx_ind_skb - flush all transmit indications from the stack
 * @net_dev: pointer to netdevice
 *
 * This function flushes all transmit indications from the stack.
 *
 * Context: The device driver must protect access to priv->tx_ind_skb, if
 * necessary.
 */
void bshdbus_flush_tx_ind_skb(struct net_device *net_dev);

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
                                  unsigned int data_len, void **data);

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
int bshdbus_push_rx_skb(struct sk_buff *skb);

/**
 * struct bshdbus_skb_priv - private additional data inside BSH D-Bus sk_buffs
 * @ifindex: ifindex of the first interface the BSH D-Bus frame appeared on TODO
 * @protocol: BSH D-Bus protocol used for this sk_buff
 * @frame_len: length of BSH D-BUS frame in data link layer
 * @dbus2_frame: align to the following BSH D-Bus frame at skb->data
 *
 * The struct bshdbus_skb_priv is used to transport additional information along
 * with the stored struct bshdbus_frame that can not be contained in existing
 * struct sk_buff elements.
 * N.B. that this information must not be modified in cloned BSH D-Bus sk_buffs.
 * To modify the BSH D-Bus frame content or the struct bshdbus_skb_priv content
 * skb_copy() needs to be used instead of skb_clone().
 */
struct bshdbus_skb_priv {
	int ifindex;		//TODO noch nicht verwendet, multiinstanz
	unsigned int protocol;
	unsigned int frame_len;
	struct bshdbus2_frame dbus2_frame[]; // TODO ist bshdbus2_frame wirklich der richtige Name? bshdbus_frame besser?
};

/**
 * bshdbus_skb_prv - return pointer to private data inside BSH D-Bus sk_buff
 * @skb: pointer to sk_buff
 *
 * Return:
 *  bshdbus_skb_prv on success
 *  NULL on failure
 */
static inline struct bshdbus_skb_priv *bshdbus_skb_prv(struct sk_buff *skb)
{
	if (unlikely(!skb))
		return NULL;

	return (struct bshdbus_skb_priv *)(skb->head);
}

/**
 * bshdbus_skb_reserve - reserve space for private data
 * @skb: pointer to sk_buff
 *
 * Return:
 *  bshdbus_skb_prv on success
 *  NULL on failure
 */
static inline void bshdbus_skb_reserve(struct sk_buff *skb)
{
	skb_reserve(skb, sizeof(struct bshdbus_skb_priv));
}

static inline void bshdbus_skb_set_owner(struct sk_buff *skb, struct sock *sk)
{
	/* If the socket has already been closed by user space, the
	 * refcount may already be 0 (and the socket will be freed
	 * after the last TX skb has been freed). So only increase
	 * socket refcount if the refcount is > 0.
	 */
	if (sk && refcount_inc_not_zero(&sk->sk_refcnt)) {
		skb->destructor = sock_efree;
		skb->sk = sk;
	}
}

/*
static inline bool can_is_can_skb(const struct sk_buff *skb)
{
	struct can_frame *cf = (struct can_frame *)skb->data;
*/
	/* the CAN specific type of skb is identified by its data length */
/*	return (skb->len == CAN_MTU && cf->len <= CAN_MAX_DLEN);
}*/

/*
static inline bool can_is_canfd_skb(const struct sk_buff *skb)
{
	struct canfd_frame *cfd = (struct canfd_frame *)skb->data;
*/
	/* the CAN specific type of skb is identified by its data length */
/*	return (skb->len == CANFD_MTU && cfd->len <= CANFD_MAX_DLEN);
}*/

/* get length element value from can[|fd|xl]_frame structure */
/*static inline unsigned int can_skb_get_len_val(struct sk_buff *skb)
{
	const struct canxl_frame *cxl = (struct canxl_frame *)skb->data;
	const struct canfd_frame *cfd = (struct canfd_frame *)skb->data;

	if (can_is_canxl_skb(skb))
		return cxl->len;

	return cfd->len;
}*/

#endif /* !_BSHDBUS_SKB_H */
