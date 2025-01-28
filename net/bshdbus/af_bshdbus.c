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

MODULE_DESCRIPTION("BSH D-Bus PF_BSHDBUS Core");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");
MODULE_ALIAS_NETPROTO(PF_BSHDBUS);

static struct kmem_cache *rcv_cache __read_mostly;

/* Table of registered BSH bus protocols */
static const struct bshdbus_proto __rcu
		*proto_tab[BSHDBUS_NPROTO] __read_mostly;
static DEFINE_MUTEX(proto_tab_lock);


#pragma GCC push_options
#pragma GCC optimize ("O0")

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
	int ret = 0;

	sock->state = SS_UNCONNECTED;

	if (protocol < 0 || protocol >=  BSHDBUS_NPROTO)
		return -EINVAL;

	proto = bshdbus_get_proto(protocol);
	if (!proto)
		return -EPROTONOSUPPORT;

	if (proto->type != sock->type) {
		ret = -EPROTOTYPE;
		goto err_put_proto;
	}

	sock->ops = proto->ops;

	sk = sk_alloc(net, PF_BSHDBUS, GFP_KERNEL, proto->prot, kern);
	if (!sk) {
		ret = -ENOMEM;
		goto err_put_proto;
	}

	sock_init_data(sock, sk);
	sk->sk_destruct = bshdbus_sock_destruct;

	if (sk->sk_prot->init)
		ret = sk->sk_prot->init(sk);

	if (ret) {
		/* release sk on errors */
		sock_orphan(sk);
		sock_put(sk);
	}

	return ret;

err_put_proto:
	bshdbus_put_proto(proto);
	return ret;
}

/**
 * bshdbus_send - transmit a BSH D-Bus frame
 * @skb: Pointer to socket buffer with BSH D-Bus frame in data section
 * @protocol: BSH D-Bus Ethernet Protocol ID
 *
 * Forward a BSH D-Bus frame to the hardware specific driver for transmitting
 * it.
 *
 * Return:
 *  0 on success
 *  -ENETDOWN when the selected interface is down
 *  -ENOBUFS on full driver queue (see net_xmit_errno())
 *  -ENOMEM when local loopback failed at calling skb_clone()
 *  -EPERM when trying to send on a non-BSH-D-Bus interface
 *  -EMSGSIZE when frame size is bigger than BSH D-Bus-2 interface MTU
 *  -EPROTONOSUPPORT when trying to set a non-BSH-D-Bus Ethernet Protocol ID
 *  -EINVAL when the skb->data does not contain a valid BSH D-Bus-2 frame
 */
int bshdbus_send(struct sk_buff *skb, __be16 protocol)
{
	int ret;

	if (unlikely(!skb))
		return -EINVAL;

	if (unlikely(protocol != htons(ETH_P_BSHDBUS2)))
		ret = -EPROTONOSUPPORT;
		goto inval_skb;

	if (unlikely(skb->len > skb->dev->mtu)) {
		ret = -EMSGSIZE;
		goto inval_skb;
	}

	if (unlikely(skb->dev->type != ARPHRD_BSHDBUS)) {
		ret = -EPERM;
		goto inval_skb;
	}

	if (unlikely(!(skb->dev->flags & IFF_UP))) {
		ret = -ENETDOWN;
		goto inval_skb;
	}

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = protocol;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	skb->pkt_type = PACKET_LOOPBACK;

	ret = dev_queue_xmit(skb);
	if (ret > 0)
		ret = net_xmit_errno(ret);

	return ret;

inval_skb:
	kfree_skb(skb);
	return ret;
}
EXPORT_SYMBOL(bshdbus_send);

static int bshdbus_map_skb_to_proto(struct sk_buff *skb, __u16 *proto)
{
	if (skb->protocol == htons(ETH_P_BSHDBUS2)) {
		*proto = BSHDBUS_DBUS2;
		return 0;
	}

	return -EINVAL;
}

static struct bshdbus_dev_rcvr_list *bshdbus_get_dev_rcvr_list(struct net *net,
		struct net_device *net_dev, __u16 proto)
{
	struct bshdbus_ml_priv *bshdbus_ml;

	if (net_dev) {
		bshdbus_ml = bshdbus_get_ml_priv(net_dev);
		if (proto == BSHDBUS_DBUS2)
			return &bshdbus_ml->bshdbus2_rcvr_list;
	}

	return NULL;
}

static inline void bshdbus_deliver(struct sk_buff *skb,
		struct bshdbus_receiver *rcvr)
{
	rcvr->deliver(skb, rcvr->data);
}

static void bshdbus_rcv_filter(struct bshdbus_dev_rcvr_list *dev_rcvr_list,
		struct sk_buff *skb)
{
	struct bshdbus_receiver *rcvr;

	if (dev_rcvr_list->entries == 0)
		return;

	hlist_for_each_entry_rcu(rcvr, &dev_rcvr_list->rcvr_list, list) {
		/* Deliver broadcast messages to all receivers */
		if (skb->pkt_type == PACKET_BROADCAST)
			bshdbus_deliver(skb, rcvr);
		/* Deliver transmit indication only to the sender of the message */
		else if (skb->pkt_type == PACKET_LOOPBACK &&
				skb->sk == rcvr->sk) {
			bshdbus_deliver(skb, rcvr);
			return;
		}
		/* Deliver addressed message only to one particular receiver */
		else if (skb->pkt_type == PACKET_USER &&
				rcvr->check_deliver(skb, rcvr->data)) {
			bshdbus_deliver(skb, rcvr);
			return;
		}
	}
}

static int bshdbus_rcv(struct sk_buff *skb, struct net_device *net_dev,
		struct packet_type *pt, struct net_device *orig_dev)
{
	struct bshdbus_dev_rcvr_list *dev_rcvr_list;
	struct net *net = dev_net(net_dev);
	__u16 proto;

	if (unlikely(net_dev->type != ARPHRD_BSHDBUS || skb->len != BSHDBUS_MTU)) {
		pr_warn_once("PF_BSHDBUS: Dropped BSHDBUS skb: dev type %d, len %d\n",
				net_dev->type, skb->len);
		goto free_skb;
	}

	if (bshdbus_map_skb_to_proto(skb, &proto)) {
		dev_err(&net_dev->dev, "Unsupported protocol type\n");
		goto free_skb;
	}

	rcu_read_lock();

	dev_rcvr_list = bshdbus_get_dev_rcvr_list(net, net_dev, proto);
	if (dev_rcvr_list)
		bshdbus_rcv_filter(dev_rcvr_list, skb);
	else
		dev_err(&net_dev->dev, "PF_BSHDBUS: Receiver list empty for dev %s\n",
		DEV_NAME(net_dev));

	rcu_read_unlock();

	consume_skb(skb);

	return NET_RX_SUCCESS;

free_skb:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static void bshdbus_rcvr_delete(struct rcu_head *rp)
{
	struct bshdbus_receiver *rcvr = container_of(rp, struct bshdbus_receiver,
			rcu);
	struct sock *sk = rcvr->sk;

	kmem_cache_free(rcv_cache, rcvr);
	if (sk)
		sock_put(sk);
}

/**
 * bshdbus_rcvr_register - subscribe BSH D-Bus frames from a specific interface
 * @net: the applicable net namespace
 * @net_dev: pointer to netdevice
 * @data: returned parameter for callback function
 * @ident: string for calling module identification
 * @deliver: callback function to deliver frame on filter match
 * @check_deliver: callback function to check filter match for addressed frame
 * @sk: socket pointer
 *
 * The check_deliver callback gets invoked for received addressed frames to find
 * the matching subscriber. Only the first matching subscriber will receive the
 * addressed frame.
 *
 * The callback function with the received sk_buff and the given parameter
 * 'data' is invoked
 *          - for all subscribers when a broadcast frame is received
 *          - for a single subscriber when the check_deliver callback matches
 *          - for a single subscriber to receive the transmit indication
 *
 * The provided pointer to the sk_buff is guaranteed to be valid as long as the
 * callback function is running. The callback function must *not* free the given
 * sk_buff while processing it's task. When the given sk_buff is needed after
 * the end of the callback function it must be cloned inside the callback
 * function with skb_clone().
 *
 * Return:
 *  0 on success
 *  -ENOMEM on missing cache mem to create subscription entry
 *  -ENODEV on unknown network device
 *  -EBUSY when socket is already registered
 *  -EINVAL when net namespace, netdevice or socket pointer is NULL
 */
int bshdbus_rcvr_register(struct net *net, struct net_device *net_dev,
		void *data, char *ident, void (*deliver)(struct sk_buff *, void *),
		bool (*check_deliver)(struct sk_buff *, void *),
		struct sock *sk)
{
	int ret = 0;
	struct bshdbus_receiver *rcvr;
	struct bshdbus_dev_rcvr_list *dev_rcvr_list;

	if (!net || !net_dev || !sk)
		return -EINVAL;

	if (net_dev->type != ARPHRD_BSHDBUS)
		return -ENODEV;

	if (!net_eq(net, dev_net(net_dev)))
		return -ENODEV;

	spin_lock_bh(&net->bshdbus.rcvlists_lock);

	dev_rcvr_list = bshdbus_get_dev_rcvr_list(net, net_dev, sk->sk_protocol);

	hlist_for_each_entry_rcu(rcvr, &dev_rcvr_list->rcvr_list, list) {
		if (rcvr->sk == sk) {
			dev_warn(&net_dev->dev, "Receiver for this sock already registered\n");
			ret = -EBUSY;
			goto leave_without_registration;
		}
	}

	rcvr = kmem_cache_alloc(rcv_cache, GFP_KERNEL);
	if (!rcvr) {
		dev_err(&net_dev->dev, "Allocate memory for receiver failed\n");
		ret = -ENOMEM;
		goto leave_without_registration;
	}

	rcvr->deliver = deliver;
	rcvr->check_deliver = check_deliver;
	rcvr->data = data;
	rcvr->ident = ident;
	rcvr->sk = sk;

	hlist_add_head_rcu(&rcvr->list, &dev_rcvr_list->rcvr_list);
	dev_rcvr_list->entries++;

leave_without_registration:
	spin_unlock_bh(&net->bshdbus.rcvlists_lock);
	return ret;
}
EXPORT_SYMBOL(bshdbus_rcvr_register);

/**
 * bshdbus_rcvr_unregister - unsubscribe BSH D-Bus frames from an interface
 * @net: the applicable net namespace
 * @net_dev: pointer to netdevice
 * @sk: socket pointer
 *
 * Removes subscription entry depending on given (subscription) values.
 */
void bshdbus_rcvr_unregister(struct net *net, struct net_device *net_dev,
		struct sock *sk)
{
	struct bshdbus_receiver *rcvr = NULL;
	struct bshdbus_dev_rcvr_list *dev_rcvr_list;

	if (!net || !net_dev || !sk)
		return;

	if (net_dev && net_dev->type != ARPHRD_BSHDBUS)
		return;

	if (net_dev && !net_eq(net, dev_net(net_dev)))
		return;

	spin_lock_bh(&net->bshdbus.rcvlists_lock);

	dev_rcvr_list = bshdbus_get_dev_rcvr_list(net, net_dev, sk->sk_protocol);
	if (!dev_rcvr_list) {
		dev_warn(&net_dev->dev, "No device receiver found\n");
		goto out;
	}

	hlist_for_each_entry_rcu(rcvr, &dev_rcvr_list->rcvr_list, list) {
		if (rcvr->sk == sk)
			break;
	}

	if (!rcvr) {
		dev_warn(&net_dev->dev, "No receiver found\n");
		goto out;
	}

	hlist_del_rcu(&rcvr->list);
	dev_rcvr_list->entries--;

out:
	spin_unlock_bh(&net->bshdbus.rcvlists_lock);

	/* schedule the receiver item for deletion */
	if (rcvr) {
		if (rcvr->sk)
			sock_hold(rcvr->sk);
		call_rcu(&rcvr->rcu, bshdbus_rcvr_delete);
	}
}
EXPORT_SYMBOL(bshdbus_rcvr_unregister);

/**
 * bshdbus_proto_register - register BSH D-Bus transport protocol
 * @proto: pointer to BSH D-Bus protocol structure
 *
 * Return:
 *  0 on success
 *  -EINVAL invalid (out of range) protocol number
 *  -EBUSY  protocol already in use
 *  -EPROTO if proto_register() fails
 */
int bshdbus_proto_register(const struct bshdbus_proto *proto)
{
	int ret;

	if (!proto) {
		pr_err("bshdbus: Invalid proto pointer\n");
		return -EINVAL;
	}

	if (proto->protocol < 0 || proto->protocol >= BSHDBUS_NPROTO) {
		pr_err("bshdbus: Protocol number %d out of range\n", proto->protocol);
		return -EINVAL;
	}

	ret = proto_register(proto->prot, 0);
	if (ret < 0)
		return -EPROTO;

	mutex_lock(&proto_tab_lock);

	if (rcu_access_pointer(proto_tab[proto->protocol])) {
		pr_err("bshdbus: Protocol %d already registered\n", proto->protocol);
		ret = -EBUSY;
	} else {
		RCU_INIT_POINTER(proto_tab[proto->protocol], proto);
	}

	mutex_unlock(&proto_tab_lock);

	if (ret < 0)
		proto_unregister(proto->prot);

	return ret;
}
EXPORT_SYMBOL(bshdbus_proto_register);

/**
 * bshdbus_proto_unregister - unregister BSH D-Bus transport protocol
 * @proto: pointer to BSH D-Bus protocol structure
 */
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
	.func = bshdbus_rcv,
};

static const struct net_proto_family bshdbus_family = {
	.family = PF_BSHDBUS,
	.create = bshdbus_create,
	.owner  = THIS_MODULE,
};

static __init int bshdbus_init(void)
{
	int ret;

	rcv_cache = kmem_cache_create("bshdbus_receiver",
			sizeof(struct bshdbus_receiver),
			0, 0, NULL);
	if (!rcv_cache)
		return -ENOMEM;

	ret = register_pernet_subsys(&bshdbus_pernet);
	if (ret)
		goto out_pernet;

	ret = sock_register(&bshdbus_family);
	if (ret)
		goto out_sock;

	dev_add_pack(&bshdbus2_packet);

	return 0;

out_sock:
	unregister_pernet_subsys(&bshdbus_pernet);
out_pernet:
	kmem_cache_destroy(rcv_cache);

	return ret;
}

static __exit void bshdbus_exit(void)
{
	sock_unregister(PF_BSHDBUS);

	unregister_pernet_subsys(&bshdbus_pernet);

	/* Wait for completion of call_rcu()'s */
	rcu_barrier();

	kmem_cache_destroy(rcv_cache);
}

#pragma GCC pop_options

module_init(bshdbus_init);
module_exit(bshdbus_exit);
