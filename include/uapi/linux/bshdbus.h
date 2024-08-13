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
#ifndef _UAPI_BSHDBUS_H
#define _UAPI_BSHDBUS_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/socket.h>

/* BSH D-Bus kernel definitions */

/* Protocols of the protocol family PF_BSHDBUS */
#define BSHDBUS_DBUS2	1 /* BSH D-Bus-2 sockets */
#define BSHDBUS_NPROTO	2

#define SOL_BSHDBUS_BASE	50
#define SOL_BSHDBUS_DBUS2	(SOL_BSHDBUS_BASE + BSHDBUS_DBUS2)

/* BSH D-Bus-2 socket options */
enum {
	BSHDBUS_DBUS2_MSG_ID = 1, /* set 0 .. n message IDs */
// TODO ist das hier richtig aufgehoben?	BSHDBUS_DBUS2_BAUD_RATE = 2, /* set baud rate for BSH D-Bus-2 */
};

/**
 * struct bshdbus_sockaddr - sockaddr structure for BSH D-Bus sockets
 * @bshdbus_family: address family number AF_BSHDBUS.
 * @ifindex: BSH D-Bus network interface index.
 * @bshdbus_addr: protocol specific address information
 */
struct bshdbus_sockaddr {
	__kernel_sa_family_t bshdbus_family;
	int ifindex;
	union {
		struct {
			__u8 addr;
		} dbus2;
	} bshdbus_addr;
};

/* BSH D-Bus-2 maximum data length */
#define BSHDBUS2_MAX_DATA_LEN 249

/**
 * BSH D-Bus-2 message ID handling
 * The message ID is divided into 1024 bit fields with 64 bit size, where every
 * BSH D-Bus-2 session can register several message ID ranges. Register the
 * message ID twice is not possible.
 * 
 * The message IDs are mapped to the structure bshdbus2_msg_id_range. For
 * example an entry for the message ID 0xFCB0 is represented with a single
 * range in the structure bshdbus2_msg_id_ranges like this:
 *     id_order = 0xFCB0 / 64 = 1010
 *     id_mask = 1 << (0xFCB0 % 64) = 48
 */

/* BSH D-Bus-2 maximum message ID order */
#define BSHDBUS2_ID_MAX_RANGES	1024
#define BSHDBUS2_IDS_PER_ORDER	64
#define BSHDBUS2_ID_MAX_ORDER	(BSHDBUS2_ID_MAX_RANGES - 1)
#define BSHDBUS2_ID_MASK_LSB	0x1
#define BSHDBUS2_ID_MASK_MSB	0x80000000

/* Convert BSH D-Bus-2 message ID high and low byte to message ID */
static inline __u16 bshdbus2_get_msg_id(__u8 msg_id_high, __u8 msg_id_low)
{
	return (msg_id_high << 8 | msg_id_low);
}

/* Get the message ID order for a message ID */
static inline __u16 bshdbus2_get_id_order(__u16 msg_id)
{
	return (msg_id / BSHDBUS2_IDS_PER_ORDER);
}

/* Get the message ID orders for the start and end message ID (ranges) */
static inline int bshdbus2_get_id_orders(__u16 msg_id_start, __u16 msg_id_end,
		__u16 *id_order_start, __u16 *id_order_end)
{
	if (msg_id_start > msg_id_end || !id_order_start || !id_order_end)
		return -EINVAL;

	*id_order_start = bshdbus2_get_id_order(msg_id_start);
	*id_order_end = bshdbus2_get_id_order(msg_id_end);
}

/* Get the message ID mask bit */
static inline __u64 bshdbus2_get_id_bit(__u16 msg_id)
{
	return (1 << (msg_id % BSHDBUS2_IDS_PER_ORDER));
}

/* Get the message ID orders and bit masks */
static inline int bshdbus2_get_id_masks(__u16 msg_id_start, __u16 msg_id_end,
		__u16 *id_order_start, __u16 *id_order_end, __u64 *id_mask_start,
		__u64 *id_mask_end)
{
	__u64 id_start_bit;
	__u64 id_end_bit;

	if (msg_id_start > msg_id_end || !id_order_start || !id_order_end ||
			!id_mask_start || !id_mask_end)
		return -EINVAL;

	bshdbus2_get_id_orders(msg_id_start, msg_id_end, id_order_start,
			id_order_end);

	id_start_bit = bshdbus2_get_id_bit(msg_id_start);

	if (msg_id_start == msg_id_end) {
		*id_mask_start = id_start_bit;
		*id_mask_end = *id_mask_start;
	}
	else {
		id_end_bit = bshdbus2_get_id_bit(msg_id_end);

		if (*id_order_start != *id_order_end) {
			*id_mask_start = (id_start_bit - BSHDBUS2_ID_MASK_LSB) |
					id_start_bit;
			*id_mask_end = (BSHDBUS2_ID_MASK_LSB - id_end_bit) |
					BSHDBUS2_ID_MASK_LSB;
		}
		else {
			*id_mask_start = (id_start_bit - id_end_bit) | id_start_bit;
			*id_mask_start = *id_mask_end;
		}
	}
}

/**
 * struct bshdbus2_msg_id_range - BSH D-Bus-2 message ID structure
 * @id_order: Message ID order
 * @id_mask: Bit mask for the particular message ID order
 */
struct bshdbus2_msg_id_range {
	__u16 id_order;
	__u64 id_mask;
};

/**
 * struct bshdbus2_msg_id_ranges - BSH D-Bus-2 message ID range structure
 * @size: Overall size of the structure
 * @range_cnt: Number of elements in the ranges array
 * @ranges: Variable array of message ID ranges
 */
struct bshdbus2_msg_id_ranges {
	__u16 range_cnt;
	struct bshdbus2_msg_id_range *ranges;
};

/**
 * struct bshdbus2_frame - BSH D-Bus-2 frame structure
 * @addr: Address byte of the D-Bus-2 frame
 * @msg_id_high: High byte of the message ID
 * @msg_id_low: Low byte of the message ID
 * @data_len: Data length in bytes
 * @flags: Message flags for D-Bus-2
 * @__res0: reserved / padding
 * @__res1: reserved / padding
 * @unique_id: Unique frame ID used for transmission only
 * @data: Data bytes
 */
struct bshdbus2_frame {
	__u8 addr;
	__u8 msg_id_high;
	__u8 msg_id_low;
	__u8 data_len;
	__u16 flags;
	__u8 __res0;
	__u8 __res1;
	__s64 unique_id;
	__u8 data[BSHDBUS2_MAX_DATA_LEN] __attribute__((aligned(8)));
};

#define BSHDBUS2_MTU (sizeof(struct bshdbus2_frame))

#endif /* !_UAPI_BSHDBUS_H */
