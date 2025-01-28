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
#include <linux/types.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <uapi/linux/bshdbus.h>

MODULE_DESCRIPTION("BSH D-Bus Netlink");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

static const struct nla_policy
	bshdbus_nl_policy_send_msg[__BSHDBUS_NLA_SEND_MSG_MAX] = {
	[BSHDBUS_NLA_SEND_MSG_UNSPEC] = { .type = NLA_UNSPEC },
	[BSHDBUS_NLA_SEND_MSG_ADDR]	= { .type = NLA_U8 },
	[BSHDBUS_NLA_SEND_MSG_ID_HIGH] = { .type = NLA_U8 },
	[BSHDBUS_NLA_SEND_MSG_ID_LOW] = { .type = NLA_U8 },
	[BSHDBUS_NLA_SEND_MSG_LEN] = { .type = NLA_U8 },
	[BSHDBUS_NLA_SEND_MSG_UNIQUE_ID] = { .type = NLA_U64 },
};

#define bshdbus_nl_err(...) pr_err("bshdbus_netlink: " __VA_ARGS__)

static int bshdbus_nl_send_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret;
	struct bshdbus2_frame *msg;
	struct nlattr *attrs[__BSHDBUS_NLA_SEND_MSG_MAX];

pr_err("%s: 1\n", __func__);
	if (!info->attrs[BSHDBUS_NLA_SEND_MSG]) {
		bshdbus_nl_err("[send_msg] Invalid attribute\n");
		return -EINVAL;
	}
pr_err("%s: 2\n", __func__);
	ret = nla_parse_nested(attrs, BSHDBUS_NLA_SEND_MSG_MAX,
				info->attrs[BSHDBUS_NLA_SEND_MSG],
				bshdbus_nl_policy_send_msg, info->extack);
	if (ret) {
		bshdbus_nl_err("[send_msg] Invalid attribute structure: %d\n", ret);
		return ret;
	}
pr_err("%s: 3\n", __func__);

//	msg = nla_data(info->attrs[BSHDBUS_ATTR_SEND_MSG]);
/*
	pr_info("Received message:\n");
	pr_info("addr: 0x%02x\n", msg->addr);
	pr_info("msg_id_high: 0x%02x\n", msg->msg_id_high);
	pr_info("msg_id_low: 0x%02x\n", msg->msg_id_low);
	pr_info("data: ");
	int i;
	for (i = 0; i < msg->data_len; i++) {
		pr_info("0x%02x\n", msg->data[i]);
	}
	pr_info("\n");
pr_err("%s: 4\n", __func__); */
	return 0;
}

static const struct nla_policy bshdbus_nl_policy[__BSHDBUS_NLA_MAX] = {
	[BSHDBUS_NLA_SEND_MSG] = { .type = NLA_NESTED }
};

static const struct genl_ops bshdbus_nl_ops[] = {
	{
		.cmd	= BSHDBUS_CMD_SEND_MSG,
		.doit	= bshdbus_nl_send_msg,
	},
};

static struct genl_family bshdbus_nl_family __ro_after_init = {
	.name		= BSHDBUS_NETLINK_NAME,
	.version	= BSHDBUS_NETLINK_VERSION,
	.module 	= THIS_MODULE,
//	.netnsok	= true,
//	.parallel_ops	= false, // TODO sollen wir parallele Operationen unterstützen?
	.maxattr	= BSHDBUS_NLA_MAX,
	.policy		= bshdbus_nl_policy,
	.ops		= bshdbus_nl_ops,
	.n_ops		= ARRAY_SIZE(bshdbus_nl_ops),
//	.mcgrps		= ethtool_nl_mcgrps,
//	.n_mcgrps	= ARRAY_SIZE(ethtool_nl_mcgrps),
};

static int __init bshdbus_nl_init(void)
{
	int ret;

	ret = genl_register_family(&bshdbus_nl_family);
	if (ret) {
		bshdbus_nl_err("Netlink registration failed: %d)\n", ret);
		return ret;
	}

/*	TODO
	ret = register_pernet_subsys(&bshdbus_nl_ops);
	if (ret) {
		pr_err("bshdbus: pernet registration failed: %d\n", ret);
		goto pernet_fail;
	} */

	return 0;

pernet_fail:
	genl_unregister_family(&bshdbus_nl_family);

	return ret;
}

static void __exit bshdbus_nl_exit(void)
{
//	unregister_pernet_subsys(&bshdbus_nl_ops); TODO
	genl_unregister_family(&bshdbus_nl_family);
}

module_init(bshdbus_nl_init);
module_exit(bshdbus_nl_exit);
