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
#ifndef BSHDBUS_ML_H
#define BSHDBUS_ML_H

#include <linux/list.h>
#include <linux/netdevice.h>

struct bshdbus_dev_rcv_lists {
	struct hlist_head rx;
	int entries;
};

struct bshdbus_ml_priv {
	struct bshdbus_dev_rcv_lists dev_rcv_lists;
};

static inline struct bshdbus_ml_priv *bshdbus_get_ml_priv(
		struct net_device *dev)
{
	return netdev_get_ml_priv(dev, ML_PRIV_BSHDBUS);
}

static inline void bshdbus_set_ml_priv(struct net_device *dev,
		struct bshdbus_ml_priv *ml_priv)
{
	netdev_set_ml_priv(dev, ml_priv, ML_PRIV_BSHDBUS);
}

#endif /* BSHDBUS_ML_H */
