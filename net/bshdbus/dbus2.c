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
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/bshdbus.h>
#include <linux/bshdbus/core.h>

MODULE_DESCRIPTION("PF_BSHDBUS D-Bus-2 protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

#define BSHDBUS2_MIN_NAMELEN BSHDBUS_REQUIRED_SIZE(struct bshdbus_sockaddr, ifindex)

struct dbus2_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct list_head notifier;
	struct bshdbus2_msg_id_ranges ids;
	struct sk_buff *skb;
	__u8 addr;
};

static LIST_HEAD(dbus2_notifier_list);
static DEFINE_SPINLOCK(dbus2_notifier_lock);
static struct dbus2_sock *dbus2_busy_notifier;

static struct dbus2_sock *bshdbus2_sk(const struct sock *sk)
{
	return (struct dbus2_sock *)sk;
}

static void bshdbus2_notify(struct dbus2_sock *dsock, unsigned long msg,
		struct net_device *dev)
{
	struct sock *sk = &dsock->sk;

	if (!net_eq(dev_net(dev), sock_net(sk)))
		return;

	if (dsock->ifindex != dev->ifindex)
		return;

	switch (msg) {
	case NETDEV_UNREGISTER:
		lock_sock(sk);

		dsock->ifindex = 0;
		dsock->bound = 0;

		release_sock(sk);

		sk->sk_err = ENODEV;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	}
}

static int bshdbus2_notifier(struct notifier_block *nb, unsigned long msg,
		void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (dev->type != ARPHRD_BSHDBUS)
		return NOTIFY_DONE;

	if (msg != NETDEV_UNREGISTER && msg != NETDEV_DOWN)
		return NOTIFY_DONE;

	/* Check for reentrant bug. */
	if (unlikely(dbus2_busy_notifier))
		return NOTIFY_DONE;

	spin_lock(&dbus2_notifier_lock);

	list_for_each_entry(dbus2_busy_notifier, &dbus2_notifier_list, notifier) {
		spin_unlock(&dbus2_notifier_lock);
		bshdbus2_notify(dbus2_busy_notifier, msg, dev);
		spin_lock(&dbus2_notifier_lock);
	}

	dbus2_busy_notifier = NULL;

	spin_unlock(&dbus2_notifier_lock);

	return NOTIFY_DONE;
}

static int bshdbus2_init(struct sock *sk)
{
	struct dbus2_sock *dsock = bshdbus2_sk(sk);

	dsock->bound = 0;
	dsock->ifindex = 0;

	spin_lock(&dbus2_notifier_lock);
	list_add_tail(&dsock->notifier, &dbus2_notifier_list);
	spin_unlock(&dbus2_notifier_lock);

	return 0;
}

static int bshdbus2_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct bshdbus_sockaddr *addr = (struct bshdbus_sockaddr *)uaddr;
	struct sock *sk = sock->sk;
	struct dbus2_sock *dsock = bshdbus2_sk(sk);
	struct net_device *dev;
	int err = 0;
	int notify_enetdown = 0;

	if (len < BSHDBUS2_MIN_NAMELEN)
		return -EINVAL;

	if (addr->bshdbus_family != AF_BSHDBUS)
		return -EINVAL;

	lock_sock(sk);

	if (dsock->bound)
		goto out;

	dev = dev_get_by_index(sock_net(sk), addr->ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}

	if (dev->type != ARPHRD_BSHDBUS) {
		dev_put(dev);
		err = -ENODEV;
		goto out;
	}

	dsock->addr = addr->bshdbus_addr.dbus2.addr;

	if (!(dev->flags & IFF_UP))
		notify_enetdown = 1;

	dev_put(dev);

	if (!err)
		dsock->bound = 1;

out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

	return err;
}

static int bshdbus2_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct dbus2_sock *dsock;
	struct net_device *dev;

	if (!sk)
		return 0;

	dsock = bshdbus2_sk(sk);

	spin_lock(&dbus2_notifier_lock);

	while (dbus2_busy_notifier == dsock) {
		spin_unlock(&dbus2_notifier_lock);
		schedule_timeout_uninterruptible(1);
		spin_lock(&dbus2_notifier_lock);
	}

	list_del(&dsock->notifier);

	spin_unlock(&dbus2_notifier_lock);

	lock_sock(sk);

	if (dsock->bound) {
		dev = dev_get_by_index(sock_net(sk), dsock->ifindex);
		if (dev) {
			// TODO unregister message ids
			dev_put(dev);
		}
	}

	dsock->ifindex = 0;
	dsock->bound = 0;

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int bshdbus2_check_id_ranges(__u16 ids_count,
		struct bshdbus2_msg_id_range *ids)
{
	int i;
	__u16 previous_id_order = -1;

	for (i = 0; i < ids_count; i++) {
		if (BSHDBUS2_ID_MAX_ORDER < ids[ids_count].id_order) {
			pr_err("bshdbus2: Message ID order %d exceeds the limit %d\n",
					ids[ids_count].id_order, BSHDBUS2_ID_MAX_ORDER);
			return -EINVAL;
		}
		else if (previous_id_order >= ids[ids_count].id_order) {
			pr_err("bshdbus2: Incorrect message ID order\n");
			return -EINVAL;
		}
	}

	return 0;
}

/* Return pointer to store the extra msg flags for bshdbus2_recvmsg().
 * We use the space of one unsigned int beyond the 'struct bshdbus_sockaddr'
 * in skb->cb.
 */
static inline unsigned int *bshdbus2_flags(struct sk_buff *skb)
{
	sock_skb_cb_check_size(sizeof(struct bshdbus_sockaddr) +
			sizeof(unsigned int));

	/* return pointer after struct bshdbus_sockaddr */
	return (unsigned int *)(&((struct bshdbus_sockaddr *)skb->cb)[1]);
}

static void bshdbus2_skb_add_sockaddr(struct sk_buff *skb)
{
	struct bshdbus_sockaddr *addr;

	sock_skb_cb_check_size(sizeof(struct bshdbus_sockaddr));

	addr = (struct bshdbus_sockaddr *)skb->cb;
	memset(addr, 0, sizeof(*addr));
	addr->bshdbus_family = AF_BSHDBUS;
	addr->ifindex = skb->dev->ifindex;
}

static void bshdbus2_rcv(struct sk_buff *oskb, void *data)
{
	struct sock *sk = (struct sock *)data;
	struct dbus2_sock *dsock = bshdbus2_sk(sk);
	struct sk_buff *skb;
	unsigned int *pflags;

	if (oskb->len != BSHDBUS2_MTU)
		return;

	dsock->skb = oskb;

	skb = skb_clone(oskb, GFP_ATOMIC);
	if (!skb)
		return;

	bshdbus2_skb_add_sockaddr(skb);

	/* Add D-Bus-2 specific message flags for bshdbus2_recvmsg() */
	pflags = bshdbus2_flags(skb);
	*pflags = 0;
	if (oskb->sk)
		*pflags |= MSG_DONTROUTE;
	if (oskb->sk == sk)
		*pflags |= MSG_CONFIRM;

	if (sock_queue_rcv_skb(sk, skb) < 0)
		kfree_skb(skb);
}

static int bshdbus2_set_msg_ids(struct socket *sock, sockptr_t optval,
		unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct dbus2_sock *dsock = bshdbus2_sk(sk);
	struct bshdbus2_msg_id_ranges *ids = NULL;
	struct bshdbus2_msg_id_range *id_ranges = NULL;
	struct net_device *dev = NULL;
	int err = 0;
	int range_cnt;

	if (optlen % sizeof(struct bshdbus2_msg_id_range) != 0)
		return -EINVAL;

	if (optlen > BSHDBUS2_ID_MAX_RANGES * sizeof(struct bshdbus2_msg_id_range))
		return -EINVAL;

	if (!dsock->bound) {
		pr_err("bshdbus2: Socket not bound yet\n");
		return -EBADF;
	}

	if (dsock->ids.range_cnt > 0) {
		pr_err("bshdbus2: Message IDs were already set\n");
		return -EPERM;
	}

	range_cnt = optlen / sizeof(struct bshdbus2_msg_id_range);
	if (range_cnt > 0) {
		id_ranges = memdup_sockptr(optval, optlen);
		if (IS_ERR(id_ranges))
			return PTR_ERR(id_ranges);
	}
	else
		return -EINVAL;

	err = bshdbus2_check_id_ranges(range_cnt, id_ranges);
	if (err) {
		kfree(id_ranges);
		return err;
	}

	dsock->ids.ranges = ids->ranges;
	dsock->ids.range_cnt = ids->range_cnt;

	rtnl_lock();
	lock_sock(sk);

	dev = dev_get_by_index(sock_net(sk), dsock->ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out_cleanup;
	}

	err = bshdbus2_rx_register(sock_net(sk), dev, dsock->addr, &dsock->ids, sk,
			"bshdbus2", bshdbus2_rcv, sk);
	if (err)
		goto out_cleanup;

out_cleanup:
	if (dev)
		dev_put(dev);

	if (err) {
		kfree(id_ranges);
		dsock->ids.range_cnt = 0;
	}

	release_sock(sk);
	rtnl_unlock();

	return err;
}

static int bshdbus2_setsockopt(struct socket *sock, int level, int optname,
		sockptr_t optval, unsigned int optlen)
{
	int err;

	if (level != SOL_BSHDBUS_DBUS2)
		return -EINVAL;

	switch (optname) {
	case BSHDBUS_DBUS2_MSG_ID:
		err = bshdbus2_set_msg_ids(sock, optval, optlen);
		break;
	default:
		return -ENOPROTOOPT;
	}

	return err;
}

static int bshdbus2_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err = 0;

// TODO check flags

	skb = skb_recv_datagram(sk, flags, &err);
	if (!skb)
		return err;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	err = memcpy_to_msg(msg, skb->data, size);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

//	sock_recv_ts_and_drops(msg, sk, skb); TODO

	if (msg->msg_name) {
		__sockaddr_check_size(BSHDBUS2_MIN_NAMELEN);
		msg->msg_namelen = BSHDBUS2_MIN_NAMELEN;
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	msg->msg_flags |= *(bshdbus2_flags(skb));

	skb_free_datagram(sk, skb);

	return size;
}

static int bshdbus2_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct dbus2_sock *dsock = bshdbus2_sk(sk);
	struct sk_buff *skb;
	struct net_device *dev;
	int ifindex;
	int err;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct bshdbus_sockaddr *, addr, msg->msg_name);

		if (msg->msg_namelen < BSHDBUS2_MIN_NAMELEN)
			return -EINVAL;

		if (addr->bshdbus_family != AF_BSHDBUS)
			return -EINVAL;

		ifindex = addr->ifindex;
	} else
		ifindex = dsock->ifindex;

	dev = dev_get_by_index(sock_net(sk), ifindex);
	if (!dev)
		return -ENXIO;
/*
	err = -EINVAL;
	if (ro->fd_frames && dev->mtu == CANFD_MTU) {
		if (unlikely(size != CANFD_MTU && size != CAN_MTU))
			goto put_dev;
	} else {
		if (unlikely(size != CAN_MTU))
			goto put_dev;
	}
*/
//	skb = sock_alloc_send_skb(sk, size + sizeof(struct can_skb_priv),
//				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto put_dev;

//	can_skb_reserve(skb);
//	can_skb_prv(skb)->ifindex = dev->ifindex;
//	can_skb_prv(skb)->skbcnt = 0;

	err = memcpy_from_msg(skb_put(skb, size), msg, size);
	if (err < 0)
		goto free_skb;

	skb_setup_tx_timestamp(skb, sk->sk_tsflags);

	skb->dev = dev;
	skb->sk = sk;
	skb->priority = sk->sk_priority;

//	err = can_send(skb, ro->loopback);

	dev_put(dev);

	if (err)
		goto send_failed;

	return size;

free_skb:
	kfree_skb(skb);
put_dev:
	dev_put(dev);
send_failed:
	return err;
}

static const struct proto_ops dbus2_ops = {
	.family = PF_BSHDBUS,
	.bind = bshdbus2_bind,
	.release = bshdbus2_release,
	.recvmsg = bshdbus2_recvmsg,
	.sendmsg = bshdbus2_sendmsg,
	.connect = sock_no_connect,
	.setsockopt = bshdbus2_setsockopt,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.gettstamp = sock_gettstamp,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.mmap = sock_no_mmap,
};

static struct proto dbus2_proto __read_mostly = {
	.name = "BSH_DBUS2",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct dbus2_sock),
	.init = bshdbus2_init,
};

static const struct bshdbus_proto bshdbus2_proto = {
	.type = SOCK_RAW,
	.protocol = BSHDBUS_DBUS2,
	.ops = &dbus2_ops,
	.prot = &dbus2_proto,
};

static struct notifier_block dbus2_notifier_block = {
	.notifier_call = bshdbus2_notifier
};

static __init int bshdbus2_module_init(void)
{
	int err;

	pr_info("bshdbus2: D-Bus-2 protocol\n");

	err = bshdbus_proto_register(&bshdbus2_proto);
	if (err)
		pr_err("bshdbus2: Register D-Bus-2 protocol failed\n");
	else {
		err = register_netdevice_notifier(&dbus2_notifier_block);
		if (err) {
			pr_err("bshdbus2: Register netdevice notifier failed\n");
			goto err_proto_unregister;
		}
	}

	return err;

err_proto_unregister:
	bshdbus_proto_unregister(&bshdbus2_proto);
	return err;
}

static __exit void bshdbus2_module_exit(void)
{
	bshdbus_proto_unregister(&bshdbus2_proto);
	unregister_netdevice_notifier(&dbus2_notifier_block);
}

module_init(bshdbus2_module_init);
module_exit(bshdbus2_module_exit);
