/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */
#ifndef __LIBSEL4_ARCH_INVOCATION_H
#define __LIBSEL4_ARCH_INVOCATION_H
enum arch_invocation_label {
    ARMPageTableMap = nSeL4ArchInvocationLabels,
    ARMPageTableUnmap,
#if defined(CONFIG_ARM_SMMU)
    ARMIOPageTableMap,
#endif
#if defined(CONFIG_ARM_SMMU)
    ARMIOPageTableUnmap,
#endif
    ARMPageMap,
    ARMPageRemap,
    ARMPageUnmap,
#if defined(CONFIG_ARM_SMMU)
    ARMPageMapIO,
#endif
    ARMPageClean_Data,
    ARMPageInvalidate_Data,
    ARMPageCleanInvalidate_Data,
    ARMPageUnify_Instruction,
    ARMPageGetAddress,
    ARMASIDControlMakePool,
    ARMASIDPoolAssign,
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
    ARMVCPUSetTCB,
#endif
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
    ARMVCPUInjectIRQ,
#endif
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
    ARMVCPUReadReg,
#endif
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
    ARMVCPUWriteReg,
#endif
    nArchInvocationLabels
};

#endif /* __LIBSEL4_ARCH_INVOCATION_H */
