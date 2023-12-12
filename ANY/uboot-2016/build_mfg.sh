#!/bin/bash
make mrproper
make O=mx6dlsabresd_config mx6dl-s3-sabresd_config
make  O=mx6dlsabresd_config u-boot.imx -j16
cp mx6dlsabresd_config/u-boot.imx mx6dlsabresd_config/u-boot-imx6dlsabresd_sd.imx

make mrproper
make O=mx6qsabresd_config mx6q-s3-sabresd_config
make O=mx6qsabresd_config u-boot.imx -j16
cp mx6qsabresd_config/u-boot.imx mx6qsabresd_config/u-boot-imx6qsabresd_sd.imx
