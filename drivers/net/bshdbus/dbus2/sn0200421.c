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
#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/bshdbus/netdev.h>

MODULE_DESCRIPTION("BSH D-Bus-2 TI SN0200421 Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

#define TIDBUS_SPI_INSTRUCTION_WRITE	(0x61 << 24)
#define TIDBUS_SPI_INSTRUCTION_READ		(0x41 << 24)

/* Message RAM configuration data length */
#define TIDBUS_MRAM_CFG_LEN	8

/* Register definitions */
#define TIDBUS_MOPC			0x800
#define TIDBUS_STATUS		0x80c
#define TIDBUS_IPEC			0x814
#define TIDBUS_DIF			0x820
#define TIDBUS_CCCR			0x4018
#define TIDBUS_DBR			0x404c
#define TIDBUS_BSA			0x4060
#define TIDBUS_BSC0			0x4064
#define TIDBUS_BSC1			0x4068
#define TIDBUS_SIDFC		0x4084

#define TIDBUS_MOPC_DEVICE_RESET	BIT(2)
#define TIDBUS_MOPC_MODE_SEL_POS	6
#define TIDBUS_MOPC_MODE_SEL_MASK	GENMASK(7, 6)

#define TIDBUS_IPEC_CCE				BIT(0)
#define TIDBUS_IPEC_DBUS_EN			BIT(2)

#define TIDBUS_DIF_POWERON			BIT(20)

#define TIDBUS_CCCR_INIT			BIT(0)
#define TIDBUS_CCCR_CCE				BIT(1)

#define TIDBUS_BSA_MRAM_ADDR		0

#define TIDBUS_BSC0_RX_BUF_SIZE_POS	16

#define TIDBUS_SIDFC_PID_POS		4
#define TIDBUS_SIDFC_LSS_MASK		GENMASK(19, 16)

enum tidbus_baud_rate
{
	TIDBUS_DBR_9600 = 0,
	TIDBUS_DBR_19200,
	TIDBUS_DBR_38400,
	TIDBUS_DBR_57600,
	TIDBUS_DBR_125000,
	TIDBUS_DBR_250000,
	TIDBUS_DBR_500000,
	TIDBUS_DBR_1000000,
};
#define TIDBUS_DBR_CLKIN_POS	3

enum tidbus_power_mode
{
	TIDBUS_POWER_MODE_SLEEP	= 0,
	TIDBUS_POWER_MODE_STANDBY = 1,
	TIDBUS_POWER_MODE_NORMAL = 2
};

enum tidbus_mram_offset {
	MRAM_SIDF = 0,
	MRAM_XIDF,
	MRAM_RXF0,
	MRAM_RXF1,
	MRAM_RXB,
	MRAM_TXE,
	MRAM_TXB,
	MRAM_CFG_NUM,
};

struct tidbus_mram_cfg {
	u16 off;
	u8  num;
};

struct __packed tidbus_buf_cmd {
	u8 cmd;
	__be16 addr;
	u8 len;
};

struct tidbus_map_buf {
	struct tidbus_buf_cmd cmd;
	u8 data[256 * sizeof(u32)];
} ____cacheline_aligned;


struct tidbus_dev {
	struct bshdbus_priv bshdbus;
	struct net_device *net_dev;
	struct device *dev;
	void *device_data;
	struct tidbus_mram_cfg mcfg[MRAM_CFG_NUM];
};

struct tidbus_priv {
	struct regmap *regmap;
	struct spi_device *spi;
	struct tidbus_dev *tdev;
	struct tidbus_map_buf map_buf_rx;
	struct tidbus_map_buf map_buf_tx;
};

static inline void tidbus_spi_cmd_set_len(struct tidbus_buf_cmd *cmd, u8 len)
{
	/* number of u32 */
	cmd->len = len >> 2;
}

static int tidbus_regmap_gather_write(void *context, const void *reg,
		size_t reg_len, const void *val, size_t val_len)
{
	struct spi_device *spi = context;
	struct tidbus_priv *priv = spi_get_drvdata(spi);
	struct tidbus_map_buf *buf_tx = &priv->map_buf_tx;
	struct spi_transfer transfer[] = {
		{
			.tx_buf = buf_tx,
			.len = sizeof(buf_tx->cmd) + val_len,
		},
	};

	memcpy(&buf_tx->cmd, reg, sizeof(buf_tx->cmd.cmd) +
			sizeof(buf_tx->cmd.addr));
	tidbus_spi_cmd_set_len(&buf_tx->cmd, val_len);
	memcpy(buf_tx->data, val, val_len);

	return spi_sync_transfer(spi, transfer, ARRAY_SIZE(transfer));
}

static int tidbus_regmap_write(void *context, const void *data, size_t count)
{
	return tidbus_regmap_gather_write(context, data, sizeof(__be32),
		data + sizeof(__be32), count - sizeof(__be32));
}

static int tidbus_regmap_read(void *context,
				const void *reg_buf, size_t reg_len,
				void *val_buf, size_t val_len)
{
	struct spi_device *spi = context;
	struct tidbus_priv *priv = spi_get_drvdata(spi);
	struct tidbus_map_buf *buf_rx = &priv->map_buf_rx;
	struct tidbus_map_buf *buf_tx = &priv->map_buf_tx;
	struct spi_transfer transfer[2] = {
		{
			.tx_buf = buf_tx,
		}
	};
	struct spi_message msg;
	int ret;

	spi_message_init(&msg);
	spi_message_add_tail(&transfer[0], &msg);

	memcpy(&buf_tx->cmd, reg_buf, sizeof(buf_tx->cmd.cmd) +
			sizeof(buf_tx->cmd.addr));
	tidbus_spi_cmd_set_len(&buf_tx->cmd, val_len);

	if (spi->controller->flags & SPI_CONTROLLER_HALF_DUPLEX) {
		transfer[0].len = sizeof(buf_tx->cmd);

		transfer[1].rx_buf = val_buf;
		transfer[1].len = val_len;
		spi_message_add_tail(&transfer[1], &msg);
	} else {
		transfer[0].rx_buf = buf_rx;
		transfer[0].len = sizeof(buf_tx->cmd) + val_len;

		memset(buf_tx->data, 0x0, val_len);
	}

	ret = spi_sync(spi, &msg);
	if (ret)
		return ret;

	if (!(spi->controller->flags & SPI_CONTROLLER_HALF_DUPLEX))
		memcpy(val_buf, buf_rx->data, val_len);

	return 0;
}

static const struct regmap_range tidbus_reg_table_wr_range[] = {
	/* Device info and SPI registers */
	regmap_reg_range(0x000c, 0x001c),
	/* Device configuration registers */
	regmap_reg_range(0x0800, 0x080c),
	regmap_reg_range(0x0814, 0x0818),
	regmap_reg_range(0x0820, 0x0820),
	regmap_reg_range(0x0830, 0x0830),
	/* TODO: CAN */
	/* TODO: Selective Wake */
	/* BSH D-Bus registers */
	regmap_reg_range(0x4010, 0x4010),
	regmap_reg_range(0x4018, 0x4018),
	regmap_reg_range(0x4020, 0x402c),
	regmap_reg_range(0x4034, 0x4034),
	regmap_reg_range(0x403c, 0x403c),
	regmap_reg_range(0x4044, 0x4044),
	regmap_reg_range(0x404c, 0x4054),
	regmap_reg_range(0x4060, 0x4074),
	regmap_reg_range(0x4080, 0x4084),
	regmap_reg_range(0x40e0, 0x40e0),
	/* BSH D-Bus message filter registers */
	regmap_reg_range(0x4200, 0x42ec),
	/* BSH D-Bus data and FIFO registers */
	regmap_reg_range(0x4400, 0x4500), // TODO abhängig von SRAM Einstellung
};

static const struct regmap_range tidbus_reg_table_rd_range[] = {
	/* Device info and SPI registers */
	regmap_reg_range(0x0000, 0x001c),
	/* Device configuration registers */
	regmap_reg_range(0x0800, 0x080c),
	regmap_reg_range(0x0814, 0x0818),
	regmap_reg_range(0x081c, 0x0828),
	regmap_reg_range(0x0830, 0x0830),
	/* TODO: CAN */
	/* TODO: Selective Wake */
	/* BSH D-Bus registers */
	regmap_reg_range(0x4000, 0x4004),
	regmap_reg_range(0x4010, 0x4010),
	regmap_reg_range(0x4018, 0x4018),
	regmap_reg_range(0x4020, 0x402c),
	regmap_reg_range(0x4034, 0x4034),
	regmap_reg_range(0x403c, 0x403c),
	regmap_reg_range(0x4044, 0x4044),
	regmap_reg_range(0x404c, 0x4054),
	regmap_reg_range(0x4060, 0x4078),
	regmap_reg_range(0x4080, 0x4084),
	regmap_reg_range(0x40a4, 0x40a4),
	regmap_reg_range(0x40c4, 0x40c4),
	regmap_reg_range(0x40e0, 0x40e0),
	regmap_reg_range(0x40f4, 0x40f4),
	/* BSH D-Bus message filter registers */
	regmap_reg_range(0x4200, 0x42ec),
	/* BSH D-Bus data and FIFO registers */
	regmap_reg_range(0x4300, 0x4500),	// TODO abhängig von SRAM Einstellung
};

static const struct regmap_access_table tidbus_reg_table_wr = {
	.yes_ranges = tidbus_reg_table_wr_range,
	.n_yes_ranges = ARRAY_SIZE(tidbus_reg_table_wr_range),
};

static const struct regmap_access_table tidbus_reg_table_rd = {
	.yes_ranges = tidbus_reg_table_rd_range,
	.n_yes_ranges = ARRAY_SIZE(tidbus_reg_table_rd_range),
};

static const struct regmap_config tidbus_regmap = {
	.reg_bits = 24,
	.reg_stride = 4,
	.pad_bits = 8,
	.val_bits = 32,
	.wr_table = &tidbus_reg_table_wr,
	.rd_table = &tidbus_reg_table_rd,
//	.max_register = TCAN4X5X_MAX_REGISTER,
	.cache_type = REGCACHE_NONE,
	.read_flag_mask = (__force unsigned long)
		cpu_to_be32(TIDBUS_SPI_INSTRUCTION_READ),
	.write_flag_mask = (__force unsigned long)
		cpu_to_be32(TIDBUS_SPI_INSTRUCTION_WRITE),
};

static const struct regmap_bus tidbus_bus = {
	.write = tidbus_regmap_write,
	.gather_write = tidbus_regmap_gather_write,
	.read = tidbus_regmap_read,
	.reg_format_endian_default = REGMAP_ENDIAN_BIG,
	.val_format_endian_default = REGMAP_ENDIAN_BIG,
	.max_raw_read = 256,	//TODO
	.max_raw_write = 256,	//TODO
};

static int tidbus_regmap_init(struct tidbus_priv *priv)
{
	priv->regmap = devm_regmap_init(&priv->spi->dev, &tidbus_bus,
			priv->spi, &tidbus_regmap);

	return PTR_ERR_OR_ZERO(priv->regmap);
}

static int tidbus_write_reg(struct tidbus_dev *tdev, int reg, u32 val)
{
	int ret;
	struct tidbus_priv *priv = tdev->device_data;

	ret = regmap_write(priv->regmap, reg, val);
	if (unlikely(ret))
		dev_err(tdev->dev, "Write register 0x%x with value 0x%x failed: %d\n",
				reg, val, ret);

	return ret;
}

static int tidbus_read_reg(struct tidbus_dev *tdev, int reg, u32 *val)
{
	int ret, value;
	struct tidbus_priv *priv = tdev->device_data;

	ret = regmap_read(priv->regmap, reg, &value);
	if (unlikely(ret))
		dev_err(tdev->dev, "Read register 0x%x failed: %d\n", reg, ret);
	else
		*val = (u32)value;

	return ret;
}

static int tidbus_set_ipec_bits(struct tidbus_dev *tdev, u32 bits, u32 bit_mask)
{
	int ret;
	u32 val;

	ret = tidbus_read_reg(tdev, TIDBUS_IPEC, &val);
	if (ret)
		goto out;

	/* Set write access */
	val |= TIDBUS_IPEC_CCE;
	ret = tidbus_write_reg(tdev, TIDBUS_IPEC, val);
	if (ret)
		goto out;

	val &= ~bit_mask;
	val |= bits;

	/* Disable write access */
	val &= ~TIDBUS_IPEC_CCE;

	ret = tidbus_write_reg(tdev, TIDBUS_IPEC, val);

out:
	return ret;
}

static int tidbus_set_power_mode(struct tidbus_dev *tdev,
		enum tidbus_power_mode mode)
{
	u32 val;

	val = tidbus_read_reg(tdev, TIDBUS_MOPC, &val);
	if (val != (mode << TIDBUS_MOPC_MODE_SEL_POS)) {
		val &= ~TIDBUS_MOPC_MODE_SEL_MASK;
		val |= mode << TIDBUS_MOPC_MODE_SEL_POS;
		return tidbus_write_reg(tdev, TIDBUS_MOPC, val);
	}

	return 0;
}

static int tidbus_set_mram_config(struct tidbus_dev *tdev)
{
	int ret;

	ret = tidbus_write_reg(tdev, TIDBUS_BSA, TIDBUS_BSA_MRAM_ADDR);
	if (!ret) {
		ret = tidbus_write_reg(tdev, TIDBUS_BSC0, (512 << TIDBUS_BSC0_RX_BUF_SIZE_POS) | 512);
		if (!ret)
			ret = tidbus_write_reg(tdev, TIDBUS_BSC1, 64);
	}

	return ret;
}

static int tidbus_set_dbus_config_mode(struct tidbus_dev *tdev)
{
	int ret;
	u32 val;

	ret = tidbus_read_reg(tdev, TIDBUS_CCCR, &val);
	if (!ret) {
		val |= TIDBUS_CCCR_INIT;
		ret = tidbus_write_reg(tdev, TIDBUS_CCCR, val);
		if (!ret) {
			val |= TIDBUS_CCCR_CCE;
			ret = tidbus_write_reg(tdev, TIDBUS_CCCR, val); // TODO geht vll in einem Schritt
		}
	}

	return ret;
}

static int tidbus_reset_chip(struct tidbus_dev *tdev, bool in_standby)
{
	u32 val;
	int ret = 0;

	if (!in_standby) {
		ret = tidbus_set_power_mode(tdev, TIDBUS_POWER_MODE_STANDBY);
	}

	if (!ret) {
		val = TIDBUS_MOPC_DEVICE_RESET |
				(TIDBUS_POWER_MODE_STANDBY << TIDBUS_MOPC_MODE_SEL_POS);
		ret = tidbus_write_reg(tdev, TIDBUS_MOPC, val);
	}

	return ret;
}

static int tidbus_clear_status_flags(struct tidbus_dev *tdev)
{
	int ret;
	u32 val;

	ret = tidbus_read_reg(tdev, TIDBUS_STATUS, &val);
	if (!ret)
		ret = tidbus_write_reg(tdev, TIDBUS_STATUS, val);

	return ret;
}

static int tidbus_init(struct tidbus_dev *tdev)
{
	int ret;
	u32 val;

	/* Chip must be in standby mode */
	ret = tidbus_set_power_mode(tdev, TIDBUS_POWER_MODE_STANDBY);
	if (ret) {
		dev_err(tdev->dev, "Set standby mode failed: %d\n", ret);
		goto out;
	}

	/* Ensure that chip is reset */
	ret = tidbus_read_reg(tdev, TIDBUS_DIF, &val);
	if (!ret) {
		if (!(val & TIDBUS_DIF_POWERON)) {
			ret = tidbus_reset_chip(tdev, true);
			if (ret) {
				dev_err(tdev->dev, "Reset chip failed: %d\n", ret);
				goto out;
			}
		}
	}
	else
		goto out;

	/* Clear interrupt flags */
	ret = tidbus_write_reg(tdev, TIDBUS_DIF, val);
	if (ret)
		goto out;

	/* Clear status flags */
	ret = tidbus_clear_status_flags(tdev);
	if (ret)
		goto out;

	/* Enabled BSH D-Bus communication */
	ret = tidbus_set_ipec_bits(tdev, TIDBUS_IPEC_DBUS_EN, TIDBUS_IPEC_DBUS_EN);
	if (!ret)
		ret = tidbus_set_dbus_config_mode(tdev);
	if (ret)
		goto out;

	/* Set baud rate */
	ret = tidbus_write_reg(tdev, TIDBUS_DBR, TIDBUS_DBR_9600);
	if (ret)
		goto out;

	/* Set MRAM configuration */
	ret = tidbus_set_mram_config(tdev);
	if (ret)
		goto out;

	/* Set maximum number of node filters */
	ret = tidbus_write_reg(tdev, TIDBUS_SIDFC, TIDBUS_SIDFC_LSS_MASK);
	if (ret)
		goto out;

	ret = tidbus_set_power_mode(tdev, TIDBUS_POWER_MODE_NORMAL);

out:
	return ret;
}

static struct tidbus_dev *alloc_tidbus_dev(struct device *dev)
{
	struct net_device *net_dev;
	struct tidbus_dev *tdev = NULL;
/*	u32 mram_config_vals[tidbus_MRAM_CFG_LEN];

	ret = fwnode_property_read_u32_array(dev_fwnode(dev),
			"bsh,mram-cfg",
			mram_config_vals,
			sizeof(mram_config_vals) / 4);
	if (ret) {
		dev_err(dev, "Could not get Message RAM configuration.");
		goto out;
	}*/

	net_dev = bshdbus_alloc_netdev(sizeof(*tdev), 0);
	if (!net_dev) {
		dev_err(dev, "Failed to allocate BSH bus device");
		goto out;
	}

	tdev = netdev_priv(net_dev);
	if (!tdev) {
		dev_err(dev, "Failed to init netdev");
		goto out;
	}

	tdev->net_dev = net_dev;
	tdev->dev = dev;
	SET_NETDEV_DEV(net_dev, dev);

/* TODO
	m_can_of_parse_mram(class_dev, mram_config_vals); */
out:
	return tdev;
}

static void free_tidbus_dev(struct net_device *net)
{
	bshdbus_free_netdev(net);
}

static int tidbus_probe(struct spi_device *spi)
{
	int ret;
	struct tidbus_priv *priv;
	struct tidbus_dev *tdev;

	tdev = alloc_tidbus_dev(&spi->dev);
	if (!tdev)
		return -ENOMEM;

	priv = devm_kzalloc(&spi->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		return -ENOMEM;
	}

/* TODO
	priv->power = devm_regulator_get_optional(&spi->dev, "vsup");
	if (PTR_ERR(priv->power) == -EPROBE_DEFER) {
		ret = -EPROBE_DEFER;
		goto out_m_can_class_free_dev;
	} else {
		priv->power = NULL;
	}
*/
	tdev->device_data = priv;

/*
	m_can_class_get_clocks(mcan_class);
	if (IS_ERR(mcan_class->cclk)) {
		dev_err(&spi->dev, "no CAN clock source defined\n");
		freq = TCAN4X5X_EXT_CLK_DEF;
	} else {
		freq = clk_get_rate(mcan_class->cclk);
	}
*/
	/* Sanity check */
/* TODO
	if (freq < 20000000 || freq > TCAN4X5X_EXT_CLK_DEF) {
		ret = -ERANGE;
		goto out_m_can_class_free_dev;
	}
*/
/* TODO
	priv->reg_offset = TCAN4X5X_MCAN_OFFSET;
	priv->mram_start = TCAN4X5X_MRAM_START;
	*/
	priv->spi = spi;
	priv->tdev = tdev;

	tdev->dev = &spi->dev;
	tdev->net_dev->irq = spi->irq;

/* TODO
	mcan_class->pm_clock_support = 0;
	mcan_class->can.clock.freq = freq;
	mcan_class->ops = &tcan4x5x_ops;
*/
	spi_set_drvdata(spi, priv);

	/* Configure the SPI bus */
	spi->bits_per_word = 32;
	ret = spi_setup(spi);
	if (ret) {
		dev_err(tdev->dev, "Setup SPI failed: %d\n", ret);
		goto err_free_tidbus_dev;
	}

	ret = tidbus_regmap_init(priv);
	if (ret) {
		dev_err(tdev->dev, "Init regmap failed: %d\n", ret);
		goto err_free_tidbus_dev;
	}

/* TODO nötig?
	ret = tcan4x5x_power_enable(priv->power, 1);
	if (ret)
		goto err_free_tidbus_dev;
*/
	ret = tidbus_init(tdev);
	if (ret) {
		dev_err(tdev->dev, "Initialize chip failed: %d\n", ret);
		goto err_free_tidbus_dev;
	}

/*

	ret = m_can_class_register(mcan_class);
	if (ret)
		goto err_power_off;
*/
	netdev_info(tdev->net_dev, "TI SN0200421 successfully initialized.\n");

	return 0;

/*err_power_off:
	tcan4x5x_power_enable(priv->power, 0); */
err_free_tidbus_dev:
	free_tidbus_dev(tdev->net_dev);
	dev_err(&spi->dev, "Probe failed, err=%d\n", ret);

	return ret;
}

static void tidbus_remove(struct spi_device *spi)
{
}

static const struct of_device_id tidbus_of_match[] = {
	{ .compatible = "ti,bshdbuscan_sn0200421", },
	{ }
};
MODULE_DEVICE_TABLE(of, tidbus_of_match);

static const struct spi_device_id tidbus_id_table[] = {
	{
		.name = "ti_bshdbuscan_sn0200421",
		.driver_data = 0,
	},
	{ }
};
MODULE_DEVICE_TABLE(spi, tidbus_id_table);

static struct spi_driver tidbus_driver = {
	.driver = {
		.name = "ti_bshdbuscan_sn0200421", // TODO besserer Name
		.of_match_table = tidbus_of_match,
		.pm = NULL,
	},
	.id_table = tidbus_id_table,
	.probe = tidbus_probe,
	.remove = tidbus_remove,
};
module_spi_driver(tidbus_driver);
