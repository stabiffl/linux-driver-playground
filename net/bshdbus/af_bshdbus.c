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
#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/bshdbus.h>
#include <linux/bshdbus/core.h>
#include <linux/bshdbus/bshdbus-ml.h>
#include "af_bshdbus.h"

MODULE_DESCRIPTION("BSH D-Bus PF_BSHDBUS core");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");
MODULE_ALIAS_NETPROTO(PF_BSHDBUS);

static struct kmem_cache *rcv_cache __read_mostly;

/* Table of registered BSH bus protocols */
static const struct bshdbus_proto __rcu
		*proto_tab[BSHDBUS_NPROTO] __read_mostly;
static DEFINE_MUTEX(proto_tab_lock);

static atomic64_t unique_id = ATOMIC_INIT(0);

static const struct bshdbus_proto *bshdbus_get_proto(int protocol)
{
	const struct bshdbus_proto *proto;

	rcu_read_lock();

	proto = rcu_dereference(proto_tab[protocol]);
	if (proto && !try_module_get(proto->prot->owner))
		proto = NULL;

	rcu_read_unlock();

	return proto;
}

static void bshdbus_put_proto(const struct bshdbus_proto *proto)
{
	module_put(proto->prot->owner);
}

static void bshdbus_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_error_queue);
}

static int bshdbus_create(struct net *net, struct socket *sock, int protocol,
		int kern)
{
	struct sock *sk;
	const struct bshdbus_proto *proto;
	int err = 0;

	sock->state = SS_UNCONNECTED;

	if (protocol < 0 || protocol >=  BSHDBUS_NPROTO)
		return -EINVAL;

	proto = bshdbus_get_proto(protocol);
	if (!proto)
		return -EPROTONOSUPPORT;

	if (proto->type != sock->type) {
		err = -EPROTOTYPE;
		goto err_put_proto;
	}

	sock->ops = proto->ops;

	sk = sk_alloc(net, PF_BSHDBUS, GFP_KERNEL, proto->prot, kern);
	if (!sk) {
		err = -ENOMEM;
		goto err_put_proto;
	}

	sock_init_data(sock, sk);
	sk->sk_destruct = bshdbus_sock_destruct;

	if (sk->sk_prot->init)
		err = sk->sk_prot->init(sk);

	if (err) {
		/* release sk on errors */
		sock_orphan(sk);
		sock_put(sk);
	}

err_put_proto:
	bshdbus_put_proto(proto);
	return err;
}

/**
 * bshdbus2_send - transmit a BSH D-Bus-2 frame
 * @skb: Pointer to socket buffer with BSH D-Bus-2 frame in data section
 *
 * Due to the loopback this routine must not be called from hardirq context.
 *
 * Return:
 *  0 on success
 *  -ENETDOWN when the selected interface is down
 *  -ENOBUFS on full driver queue (see net_xmit_errno())
 *  -ENOMEM when local loopback failed at calling skb_clone()
 *  -EPERM when trying to send on a non-BSH-D-Bus interface
 *  -EMSGSIZE CAN frame size is bigger than BSH D-Bus-2 interface MTU
 *  -EINVAL when the skb->data does not contain a valid BSH D-Bus-2 frame
 */
int bshdbus2_send(struct sk_buff *skb)
{
	int err = -EINVAL;
	struct sk_buff *newskb = NULL;
	struct bshdbus2_frame *dbus2_frame = (struct bshdbus2_frame *)skb->data;

	if (unlikely(skb->len == BSHDBUS2_MTU)) {
		skb->protocol = htons(ETH_P_BSHDBUS2);
		if (unlikely(dbus2_frame->data_len > BSHDBUS2_MAX_DATA_LEN))
			goto inval_skb;
	} else {
		goto inval_skb;
	}

	if (unlikely(skb->len > skb->dev->mtu)) {
		err = -EMSGSIZE;
		goto inval_skb;
	}

	if (unlikely(skb->dev->type != ARPHRD_BSHDBUS)) {
		err = -EPERM;
		goto inval_skb;
	}

	if (unlikely(!(skb->dev->flags & IFF_UP))) {
		err = -ENETDOWN;
		goto inval_skb;
	}

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	/* indication for the BSH D-Bus driver: do loopback */
	skb->pkt_type = PACKET_LOOPBACK;

	if (!(skb->dev->flags & IFF_ECHO)) {
		/* If the interface is not capable to do loopback
		 * itself, we do it here.
		 */
		newskb = skb_clone(skb, GFP_ATOMIC);
		if (!newskb) {
			kfree_skb(skb);
			return -ENOMEM;
		}

		/* If the socket has already been closed by user space, the
		 * refcount may already be 0 (and the socket will be freed
		 * after the last TX skb has been freed). So only increase
		 * socket refcount if the refcount is > 0.
		 */
		if (skb->sk && refcount_inc_not_zero(&skb->sk->sk_refcnt)) {
			newskb->destructor = sock_efree;
			newskb->sk = skb->sk;
		}
		newskb->ip_summed = CHECKSUM_UNNECESSARY;
		newskb->pkt_type = PACKET_BROADCAST;
	}

	err = dev_queue_xmit(skb);
	if (err > 0)
		err = net_xmit_errno(err);

	if (err) {
		kfree_skb(newskb);
		return err;
	}

	if (newskb)
		netif_rx(newskb);

	return 0;

inval_skb:
	kfree_skb(skb);
	return err;
}
EXPORT_SYMBOL(bshdbus2_send);

static struct bshdbus_dev_rcv_lists *bshdbus_dev_rcv_lists_find(struct net *net,
		struct net_device *dev)
{
	struct bshdbus_ml_priv *bshdbus_ml;

	if (dev) {
		bshdbus_ml = bshdbus_get_ml_priv(dev);
		return &bshdbus_ml->dev_rcv_lists;
	}

	return NULL;
}

static inline void bshdbus2_deliver(struct sk_buff *skb,
		struct bshdbus2_receiver *rcv)
{
	rcv->func(skb, rcv->data);
}

static void bshdbus2_frame_add_unique_id(struct bshdbus2_frame *dbus2_frame)
{
	while (!(dbus2_frame->unique_id))
		dbus2_frame->unique_id = atomic64_inc_return(&unique_id);
}

static bool bshdbus2_is_broadcast_msg(__u8 addr)
{
	if (0x00 == (addr & 0xF0))
		return true;
	
	return false;
}

static bool bshdbus2_is_msg_id_registered(__u16 msg_id_high, __u16 msg_id_low,
		struct bshdbus2_msg_id_ranges *ids)
{
	__u16 cnt;
	__u16 id_bit;
	__u16 id_order;
	__u16 msg_id = bshdbus2_get_msg_id(msg_id_high, msg_id_low);
	struct bshdbus2_msg_id_range *range;

	id_bit = bshdbus2_get_id_bit(msg_id);
	id_order = bshdbus2_get_id_order(msg_id);

	for (cnt = 0; cnt < ids->range_cnt; cnt++) {
		range = &ids->ranges[cnt];

		if (id_order == range->id_order && (id_bit & range->id_mask))
			/* Entry found */
			return true;
		/* Ranges are ordered by their ID order, quit searching if only higher
		 * orders exist
		 */
		else if (id_order < range->id_order) {
			break;
		}
	}

	return false;
}

static void bshdbus2_rcv_filter(struct bshdbus_dev_rcv_lists *dev_rcv_lists,
		struct sk_buff *skb)
{
	struct bshdbus2_receiver *rcv;
	struct bshdbus2_frame *dbus2_frame = (struct bshdbus2_frame *)skb->data;

	if (dev_rcv_lists->entries == 0)
		return;

	hlist_for_each_entry_rcu(rcv, &dev_rcv_lists->rx, list) {
		/* Deliver broadcast messages to all receivers */
		if (bshdbus2_is_broadcast_msg(dbus2_frame->addr))
			bshdbus2_deliver(skb, rcv);
		/* Deliver addressed message only to one particular receiver */
		else if (dbus2_frame->addr == rcv->addr &&
				bshdbus2_is_msg_id_registered(dbus2_frame->msg_id_high,
						dbus2_frame->msg_id_low, rcv->ids)) {
			bshdbus2_deliver(skb, rcv);
			return;
		}
	}
}

static void bshdbus2_receive(struct sk_buff *skb, struct net_device *dev)
{
	struct bshdbus_dev_rcv_lists *dev_rcv_lists;
	struct net *net = dev_net(dev);

	rcu_read_lock();

	dev_rcv_lists = bshdbus_dev_rcv_lists_find(net, dev);
	if (dev_rcv_lists)
		bshdbus2_rcv_filter(dev_rcv_lists, skb);
	else
		dev_err(&dev->dev, "PF_BSHDBUS: Receiver list empty for dev %s\n",
		DEV_NAME(dev));

	rcu_read_unlock();

	consume_skb(skb);
}

static int bshdbus2_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev)
{
	struct bshdbus2_frame *dbus2_frame = (struct bshdbus2_frame *)skb->data;

	if (unlikely(dev->type != ARPHRD_BSHDBUS || skb->len != BSHDBUS2_MTU)) {
		pr_warn_once("PF_BSHDBUS: Dropped BSHDBUS skb: dev type %d, len %d\n",
				dev->type, skb->len);
		goto free_skb;
	}

	bshdbus2_frame_add_unique_id(dbus2_frame);

	bshdbus2_receive(skb, dev);

	return NET_RX_SUCCESS;

free_skb:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static struct hlist_head *bshdbus2_rcv_list_find(__u8 addr,
		struct bshdbus_dev_rcv_lists *dev_rcv_lists)
{
	return &dev_rcv_lists->rx;
}

int bshdbus2_rx_register(struct net *net, struct net_device *dev, __u8 addr,
		struct bshdbus2_msg_id_ranges *ids, void *data, char *ident,
		void (*func)(struct sk_buff *, void *), struct sock *sk)
{
	int err;
	struct hlist_head *rcv_list;
	struct bshdbus2_receiver *rcv;
	struct bshdbus_dev_rcv_lists *dev_rcv_lists;

	if (dev && dev->type != ARPHRD_BSHDBUS)
		return -ENODEV;

	if (dev && !net_eq(net, dev_net(dev)))
		return -ENODEV;

	rcv = kmem_cache_alloc(rcv_cache, GFP_KERNEL);
	if (!rcv)
		return -ENOMEM;

	spin_lock_bh(&net->bshdbus.rcvlists_lock);

	dev_rcv_lists = bshdbus_dev_rcv_lists_find(net, dev);
	rcv_list = bshdbus2_rcv_list_find(addr, dev_rcv_lists);

	rcv->addr = addr;
	rcv->func = func;
	rcv->data = data;
	rcv->ident = ident;
	rcv->ids = ids;
	rcv->sk = sk;

	hlist_add_head_rcu(&rcv->list, rcv_list);
	dev_rcv_lists->entries++;

	spin_unlock_bh(&net->bshdbus.rcvlists_lock);

	return err;
}
EXPORT_SYMBOL(bshdbus2_rx_register);

static void bshdbus2_rx_delete_receiver(struct rcu_head *rp)
{
	struct bshdbus2_receiver *rcv = container_of(rp, struct bshdbus2_receiver,
			rcu);
	struct sock *sk = rcv->sk;

	kmem_cache_free(rcv_cache, rcv);
	if (sk)
		sock_put(sk);
}

void bshdbus2_rx_unregister(struct net *net, struct net_device *dev, __u8 addr,
		struct bshdbus2_msg_id_ranges *ids)
{
	struct hlist_head *rcv_list;
	struct bshdbus2_receiver *rcv = NULL;
	struct bshdbus_dev_rcv_lists *dev_rcv_lists;

	if (dev && dev->type != ARPHRD_BSHDBUS)
		return;

	if (dev && !net_eq(net, dev_net(dev)))
		return;

	spin_lock_bh(&net->bshdbus.rcvlists_lock);

	dev_rcv_lists = bshdbus_dev_rcv_lists_find(net, dev);
	rcv_list = bshdbus2_rcv_list_find(addr, dev_rcv_lists);

	/* A message ID can be only registered once, find the receiver */
	hlist_for_each_entry_rcu(rcv, rcv_list, list) {
		if (rcv->addr == addr && 
				rcv->ids->ranges[0].id_order == ids->ranges[0].id_order &&
				rcv->ids->ranges[0].id_mask == ids->ranges[0].id_mask)
			break;
	}

	if (!rcv) {
		dev_warn(&dev->dev, "PF_BSHDBUS: No receive list, dev %s, addr %02x, \
				id_order %d, id_mask %08llx\n", DEV_NAME(dev), addr,
				ids->ranges[0].id_order, ids->ranges[0].id_mask);
		goto out;
	}

	hlist_del_rcu(&rcv->list);
	dev_rcv_lists->entries--;

out:
	spin_unlock_bh(&net->bshdbus.rcvlists_lock);

	/* schedule the receiver item for deletion */
	if (rcv) {
		if (rcv->sk)
			sock_hold(rcv->sk);
		call_rcu(&rcv->rcu, bshdbus2_rx_delete_receiver);
	}
}
EXPORT_SYMBOL(bshdbus2_rx_unregister);

int bshdbus_proto_register(const struct bshdbus_proto *proto)
{
	int err;

	if (!proto) {
		pr_err("bshdbus: Invalid proto pointer\n");
		return -EINVAL;
	}

	if (proto->protocol < 0 || proto->protocol >= BSHDBUS_NPROTO) {
		pr_err("bshdbus: Protocol number %d out of range\n", proto->protocol);
		return -EINVAL;
	}

	err = proto_register(proto->prot, 0);
	if (err < 0)
		return err;

	mutex_lock(&proto_tab_lock);

	if (rcu_access_pointer(proto_tab[proto->protocol])) {
		pr_err("bshdbus: Protocol %d already registered\n", proto->protocol);
		err = -EBUSY;
	} else {
		RCU_INIT_POINTER(proto_tab[proto->protocol], proto);
	}

	mutex_unlock(&proto_tab_lock);

	if (err < 0)
		proto_unregister(proto->prot);

	return err;
}
EXPORT_SYMBOL(bshdbus_proto_register);

void bshdbus_proto_unregister(const struct bshdbus_proto *proto)
{
	if (!proto) {
		pr_err("bshdbus: Invalid proto pointer\n");
		return;
	}

	mutex_lock(&proto_tab_lock);
	BUG_ON(rcu_access_pointer(proto_tab[proto->protocol]) != proto);
	RCU_INIT_POINTER(proto_tab[proto->protocol], NULL);
	mutex_unlock(&proto_tab_lock);

	synchronize_rcu();

	proto_unregister(proto->prot);
}
EXPORT_SYMBOL(bshdbus_proto_unregister);

static int bshdbus_pernet_init(struct net *net)
{
	/* Nothing to do so far */
	return 0;
}

static void bshdbus_pernet_exit(struct net *net)
{
	/* Nothing to do so far */
}

static struct pernet_operations bshdbus_pernet __read_mostly = {
	.init = bshdbus_pernet_init,
	.exit = bshdbus_pernet_exit,
};

static struct packet_type bshdbus2_packet __read_mostly = {
	.type = cpu_to_be16(ETH_P_BSHDBUS2),
	.func = bshdbus2_rcv,
};

static const struct net_proto_family bshdbus_family = {
	.family = PF_BSHDBUS,
	.create = bshdbus_create,
	.owner  = THIS_MODULE,
};

static __init int bshdbus_init(void)
{
	int err;

	pr_info("bshdbus: BSH D-Bus core\n");

	rcv_cache = kmem_cache_create("bshdbus2_receiver",
			sizeof(struct bshdbus2_receiver),
			0, 0, NULL);
	if (!rcv_cache)
		return -ENOMEM;

	err = register_pernet_subsys(&bshdbus_pernet);
	if (err)
		goto out_pernet;

	err = sock_register(&bshdbus_family);
	if (err)
		goto out_sock;

	dev_add_pack(&bshdbus2_packet);

	return 0;

out_sock:
	unregister_pernet_subsys(&bshdbus_pernet);
out_pernet:
	kmem_cache_destroy(rcv_cache);

	return err;
}

static __exit void bshdbus_exit(void)
{
	sock_unregister(PF_BSHDBUS);

	unregister_pernet_subsys(&bshdbus_pernet);

	/* Wait for completion of call_rcu()'s */
	rcu_barrier();

	kmem_cache_destroy(rcv_cache);
}

module_init(bshdbus_init);
module_exit(bshdbus_exit);
