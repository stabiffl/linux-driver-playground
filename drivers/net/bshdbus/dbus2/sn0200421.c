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
#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/bshdbus/dev.h>

MODULE_DESCRIPTION("BSH D-Bus-2 SN0200421 driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wolfgang Birkner <wolfgang.birkner@bshg.com>");

/* Message RAM configuration data length */
#define DBUS2SN_MRAM_CFG_LEN	8

/* Register definitions */
enum dbus2sn_reg {
	DBUS2SN_CREL	= 0x4000,
};

enum dbus2sn_mram_offset {
	MRAM_SIDF = 0,
	MRAM_XIDF,
	MRAM_RXF0,
	MRAM_RXF1,
	MRAM_RXB,
	MRAM_TXE,
	MRAM_TXB,
	MRAM_CFG_NUM,
};

struct dbus2sn_mram_cfg {
	u16 off;
	u8  num;
};

struct dbus2sn_dev {
	struct bshdbus_priv bshdbus;
	struct net_device *net;
	struct device *dev;
	void *device_data;
	struct dbus2sn_mram_cfg mcfg[MRAM_CFG_NUM];
};

struct dbus2sn_priv {
	struct regmap *regmap;
	struct spi_device *spi;
	struct dbus2sn_dev *sn_dev;
};

static int write_dbus2sn_reg(struct dbus2sn_dev *sn_dev, enum dbus2sn_reg reg,
		u32 val)
{
	int ret;
	struct dbus2sn_priv *priv = sn_dev->device_data;

	ret = regmap_write(priv->regmap, reg, val);
	if (unlikely(ret))
		dev_err(sn_dev->dev, "Write register 0x%x failed: %d\n", reg, ret);

	return ret;
}

static int read_dbus2sn_reg(struct dbus2sn_dev *sn_dev, enum dbus2sn_reg reg,
		u32 *val)
{
	int ret;
	struct dbus2sn_priv *priv = sn_dev->device_data;

	ret = regmap_read(priv->regmap, reg, val);
	if (unlikely(ret))
		dev_err(sn_dev->dev, "Read register 0x%x failed: %d\n", reg, ret);

	return ret;
}

static struct dbus2sn_dev *alloc_dbus2sn_dev(struct device *dev)
{
	int ret;
	struct net_device *net_dev;
	struct dbus2sn_dev *sn_dev = NULL;
	u32 mram_config_vals[DBUS2SN_MRAM_CFG_LEN];

	ret = fwnode_property_read_u32_array(dev_fwnode(dev),
			"bsh,mram-cfg",
			mram_config_vals,
			sizeof(mram_config_vals) / 4);
	if (ret) {
		dev_err(dev, "Could not get Message RAM configuration.");
		goto out;
	}

	net_dev = bshdbus_alloc_dev(sizeof(*sn_dev), 0);
	if (!net_dev) {
		dev_err(dev, "Failed to allocate BSH bus device");
		goto out;
	}

	sn_dev = netdev_priv(net_dev);
	if (!sn_dev) {
		dev_err(dev, "Failed to init netdev");
		goto out;
	}

	sn_dev->net = net_dev;
	sn_dev->dev = dev;
	SET_NETDEV_DEV(net_dev, dev);

/* TODO 
	m_can_of_parse_mram(class_dev, mram_config_vals); */
out:
	return sn_dev;
}

static void free_dbus2sn_dev(struct net_device *net)
{
	bshdbus_free_dev(net);
}

static int dbus2sn_probe(struct spi_device *spi)
{
	int ret;
	struct dbus2sn_priv *priv;
	struct dbus2sn_dev *sn_dev;

	sn_dev = alloc_dbus2sn_dev(&spi->dev);
	if (!sn_dev)
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
	sn_dev->device_data = priv;

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
	priv->sn_dev = sn_dev;

	sn_dev->dev = &spi->dev;
	sn_dev->net->irq = spi->irq;

/* TODO 
	mcan_class->pm_clock_support = 0;
	mcan_class->can.clock.freq = freq;
	mcan_class->ops = &tcan4x5x_ops;
*/
	spi_set_drvdata(spi, priv);

	/* Configure the SPI bus */
	spi->bits_per_word = 32;
	ret = spi_setup(spi);
	if (ret)
		goto err_free_dbus2sn_dev;

/* TODO 
	priv->regmap = devm_regmap_init(&spi->dev, &tcan4x5x_bus,
					&spi->dev, &tcan4x5x_regmap);
	if (IS_ERR(priv->regmap)) {
		ret = PTR_ERR(priv->regmap);
		goto err_free_dbus2sn_dev;
	} */

/* TODO nötig?
	ret = tcan4x5x_power_enable(priv->power, 1);
	if (ret)
		goto err_free_dbus2sn_dev;
*/
/*
	ret = tcan4x5x_init(mcan_class);
	if (ret)
		goto err_power_off;

	ret = m_can_class_register(mcan_class);
	if (ret)
		goto err_power_off;
*/
	netdev_info(sn_dev->net, "SN0200421 successfully initialized.\n");

	return 0;

/*err_power_off:
	tcan4x5x_power_enable(priv->power, 0); */
err_free_dbus2sn_dev:
	free_dbus2sn_dev(sn_dev->net);
	dev_err(&spi->dev, "Probe failed, err=%d\n", ret);

	return ret;
}

static void dbus2sn_remove(struct spi_device *spi)
{
}

static const struct of_device_id dbus2sn_of_match[] = {
	{ .compatible = "ti,sn0200421", },
	{ }
};
MODULE_DEVICE_TABLE(of, dbus2sn_of_match);

static const struct spi_device_id dbus2sn_id_table[] = {
	{
		.name = "sn0200421",
		.driver_data = 0,
	},
	{ }
};
MODULE_DEVICE_TABLE(spi, dbus2sn_id_table);

static struct spi_driver dbus2sn_driver = {
	.driver = {
		.name = "sn0200421",
		.of_match_table = dbus2sn_of_match,
		.pm = NULL,
	},
	.id_table = dbus2sn_id_table,
	.probe = dbus2sn_probe,
	.remove = dbus2sn_remove,
};
module_spi_driver(dbus2sn_driver);
