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
#ifndef _BSHDBUS_CORE_H
#define _BSHDBUS_CORE_H

#include <linux/netdevice.h>

#define DEV_NAME(dev) ((dev) ? (dev)->name : "any")

/* Macro to find the minimum size of a struct that includes a requested
 * member
 */
#define BSHDBUS_REQUIRED_SIZE(struct_type, member) \
	(offsetof(typeof(struct_type), member) + \
	sizeof(((typeof(struct_type) *)(NULL))->member))

/**
 * struct bshdbus_proto - BSH D-Bus protocol structure
 * @type: type argument in socket() syscall, e.g. SOCK_RAW.
 * @protocol: protocol number in socket() syscall.
 * @ops: pointer to struct proto_ops for sock->ops.
 * @prot: pointer to struct proto structure.
 */
struct bshdbus_proto {
	int type;
	int protocol;
	const struct proto_ops *ops;
	struct proto *prot;
};

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
extern int  bshdbus_proto_register(const struct bshdbus_proto *proto);

/**
 * bshdbus_proto_unregister - unregister BSH D-Bus transport protocol
 * @proto: pointer to BSH D-Bus protocol structure
 */
extern void bshdbus_proto_unregister(const struct bshdbus_proto *proto);

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
int bshdbus_rcvr_register(struct net *net, struct net_device *dev, void *data,
		char *ident, void (*deliver)(struct sk_buff *, void *),
		bool (*check_deliver)(struct sk_buff *, void *), struct sock *sk);

/**
 * bshdbus_rcvr_unregister - unsubscribe BSH D-Bus frames from an interface
 * @net: the applicable net namespace
 * @net_dev: pointer to netdevice
 * @sk: socket pointer
 *
 * Removes subscription entry depending on given (subscription) values.
 */
void bshdbus_rcvr_unregister(struct net *net, struct net_device *dev,
		struct sock *sk);

/* (Un)register BSH D-Bus-2 message receiption via receiver */
//int bshdbus2_rcvr_id_register(__u8 addr, struct bshdbus2_msg_id_ranges *ids);
//void bshdbus2_rcvr_id_unregister(__u8 addr, struct bshdbus2_msg_id_ranges *ids);

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
int bshdbus_send(struct sk_buff *skb, __be16 protocol);

#endif /* !_BSHDBUS_CORE_H */
