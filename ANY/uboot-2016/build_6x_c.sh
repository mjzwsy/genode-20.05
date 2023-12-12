#!/bin/bash

make distclean
make mx6q-c-sabresd_defconfig
make -j5
cp u-boot.imx uboot-6q.tran

make distclean
make mx6dl-c-sabresd_defconfig
make -j16
cp u-boot.imx uboot-6dl.tran

make distclean
make mx6q-c-2g-sabresd_defconfig
make -j5
cp u-boot.imx uboot-6q-2g.tran

make distclean
make mx6dl-c-2g-sabresd_defconfig
make -j16
cp u-boot.imx uboot-6dl-2g.tran

mv uboot-6q.tran u-boot-6q.imx
mv uboot-6dl.tran u-boot-6dl.imx
mv uboot-6q-2g.tran u-boot-6q-2g.imx
mv uboot-6dl-2g.tran u-boot-6dl-2g.imx
