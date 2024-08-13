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

/**
 * struct bshdbus_proto - BSH D-Bus protocol structure
 * @type:       type argument in socket() syscall, e.g. SOCK_RAW.
 * @protocol:   protocol number in socket() syscall.
 * @ops:        pointer to struct proto_ops for sock->ops.
 * @prot:       pointer to struct proto structure.
 */
struct bshdbus_proto {
	int type;
	int protocol;
	const struct proto_ops *ops;
	struct proto *prot;
};

/* (Un)register a protocol for the BSH D-Bus network layer */
extern int  bshdbus_proto_register(const struct bshdbus_proto *proto);
extern void bshdbus_proto_unregister(const struct bshdbus_proto *proto);

/* (Un)register message reception for BSH D-Bus-2 */
int bshdbus2_rx_register(struct net *net, struct net_device *dev, __u8 addr,
		struct bshdbus2_msg_id_ranges *ids, void *data, char *ident,
		void (*func)(struct sk_buff *, void *), struct sock *sk);
void bshdbus2_rx_unregister(struct net *net, struct net_device *dev, __u8 addr,
		struct bshdbus2_msg_id_ranges *ids);

/* Macro to find the minimum size of a struct that includes a requested
 * member
 */
#define BSHDBUS_REQUIRED_SIZE(struct_type, member) \
	(offsetof(typeof(struct_type), member) + \
	sizeof(((typeof(struct_type) *)(NULL))->member))


/* Send BSH D-Bus-2 frame */
int bshdbus2_send(struct sk_buff *skb);

#endif /* !_BSHDBUS_CORE_H */
