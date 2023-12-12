#ifndef _HOME_SIYUAN_GENODE_20_05_BUILD_ARM_V7A_VAR_LIBCACHE_SYSCALL_SEL4_INCLUDE_SEL4_SEL4_ARCH_TYPES_GEN_H
#define _HOME_SIYUAN_GENODE_20_05_BUILD_ARM_V7A_VAR_LIBCACHE_SYSCALL_SEL4_INCLUDE_SEL4_SEL4_ARCH_TYPES_GEN_H

#include <autoconf.h>
#include <sel4/simple_types.h>
#include <sel4/debug_assert.h>
struct seL4_Fault {
    seL4_Uint32 words[14];
};
typedef struct seL4_Fault seL4_Fault_t;

enum seL4_Fault_tag {
    seL4_Fault_NullFault = 0,
    seL4_Fault_CapFault = 1,
    seL4_Fault_UnknownSyscall = 2,
    seL4_Fault_UserException = 3,
    seL4_Fault_VMFault = 5
};
typedef enum seL4_Fault_tag seL4_Fault_tag_t;

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_get_seL4_FaultType(seL4_Fault_t seL4_Fault) {
    return (seL4_Fault.words[0] >> 0) & 0x7u;
}

LIBSEL4_INLINE_FUNC int CONST
seL4_Fault_seL4_FaultType_equals(seL4_Fault_t seL4_Fault, seL4_Uint32 seL4_Fault_type_tag) {
    return ((seL4_Fault.words[0] >> 0) & 0x7u) == seL4_Fault_type_tag;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_ptr_get_seL4_FaultType(seL4_Fault_t *seL4_Fault_ptr) {
    return (seL4_Fault_ptr->words[0] >> 0) & 0x7u;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_NullFault_new(void) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_NullFault & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_NullFault & (1u << 31))) ? 0x0 : 0));

    seL4_Fault.words[0] = 0
        | ((seL4_Uint32)seL4_Fault_NullFault & 0x7u) << 0;
    seL4_Fault.words[1] = 0;
    seL4_Fault.words[2] = 0;
    seL4_Fault.words[3] = 0;
    seL4_Fault.words[4] = 0;
    seL4_Fault.words[5] = 0;
    seL4_Fault.words[6] = 0;
    seL4_Fault.words[7] = 0;
    seL4_Fault.words[8] = 0;
    seL4_Fault.words[9] = 0;
    seL4_Fault.words[10] = 0;
    seL4_Fault.words[11] = 0;
    seL4_Fault.words[12] = 0;
    seL4_Fault.words[13] = 0;

    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_NullFault_ptr_new(seL4_Fault_t *seL4_Fault_ptr) {
    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_NullFault & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_NullFault & (1u << 31))) ? 0x0 : 0));

    seL4_Fault_ptr->words[0] = 0
        | ((seL4_Uint32)seL4_Fault_NullFault & 0x7u) << 0;
    seL4_Fault_ptr->words[1] = 0;
    seL4_Fault_ptr->words[2] = 0;
    seL4_Fault_ptr->words[3] = 0;
    seL4_Fault_ptr->words[4] = 0;
    seL4_Fault_ptr->words[5] = 0;
    seL4_Fault_ptr->words[6] = 0;
    seL4_Fault_ptr->words[7] = 0;
    seL4_Fault_ptr->words[8] = 0;
    seL4_Fault_ptr->words[9] = 0;
    seL4_Fault_ptr->words[10] = 0;
    seL4_Fault_ptr->words[11] = 0;
    seL4_Fault_ptr->words[12] = 0;
    seL4_Fault_ptr->words[13] = 0;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_new(seL4_Uint32 IP, seL4_Uint32 Addr, seL4_Uint32 InRecvPhase, seL4_Uint32 LookupFailureType, seL4_Uint32 MR4, seL4_Uint32 MR5, seL4_Uint32 MR6) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_CapFault & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_CapFault & (1u << 31))) ? 0x0 : 0));

    seL4_Fault.words[0] = 0
        | ((seL4_Uint32)seL4_Fault_CapFault & 0x7u) << 0;
    seL4_Fault.words[1] = 0
        | MR6 << 0;
    seL4_Fault.words[2] = 0
        | MR5 << 0;
    seL4_Fault.words[3] = 0
        | MR4 << 0;
    seL4_Fault.words[4] = 0
        | LookupFailureType << 0;
    seL4_Fault.words[5] = 0
        | InRecvPhase << 0;
    seL4_Fault.words[6] = 0
        | Addr << 0;
    seL4_Fault.words[7] = 0
        | IP << 0;
    seL4_Fault.words[8] = 0;
    seL4_Fault.words[9] = 0;
    seL4_Fault.words[10] = 0;
    seL4_Fault.words[11] = 0;
    seL4_Fault.words[12] = 0;
    seL4_Fault.words[13] = 0;

    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_new(seL4_Fault_t *seL4_Fault_ptr, seL4_Uint32 IP, seL4_Uint32 Addr, seL4_Uint32 InRecvPhase, seL4_Uint32 LookupFailureType, seL4_Uint32 MR4, seL4_Uint32 MR5, seL4_Uint32 MR6) {
    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_CapFault & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_CapFault & (1u << 31))) ? 0x0 : 0));

    seL4_Fault_ptr->words[0] = 0
        | ((seL4_Uint32)seL4_Fault_CapFault & 0x7u) << 0;
    seL4_Fault_ptr->words[1] = 0
        | MR6 << 0;
    seL4_Fault_ptr->words[2] = 0
        | MR5 << 0;
    seL4_Fault_ptr->words[3] = 0
        | MR4 << 0;
    seL4_Fault_ptr->words[4] = 0
        | LookupFailureType << 0;
    seL4_Fault_ptr->words[5] = 0
        | InRecvPhase << 0;
    seL4_Fault_ptr->words[6] = 0
        | Addr << 0;
    seL4_Fault_ptr->words[7] = 0
        | IP << 0;
    seL4_Fault_ptr->words[8] = 0;
    seL4_Fault_ptr->words[9] = 0;
    seL4_Fault_ptr->words[10] = 0;
    seL4_Fault_ptr->words[11] = 0;
    seL4_Fault_ptr->words[12] = 0;
    seL4_Fault_ptr->words[13] = 0;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_IP(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[7] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_IP(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[7] &= ~0xffffffffu;
    seL4_Fault.words[7] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_IP(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[7] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_IP(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[7] &= ~0xffffffffu;
    seL4_Fault_ptr->words[7] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_Addr(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[6] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_Addr(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[6] &= ~0xffffffffu;
    seL4_Fault.words[6] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_Addr(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[6] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_Addr(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[6] &= ~0xffffffffu;
    seL4_Fault_ptr->words[6] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_InRecvPhase(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[5] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_InRecvPhase(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[5] &= ~0xffffffffu;
    seL4_Fault.words[5] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_InRecvPhase(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[5] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_InRecvPhase(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[5] &= ~0xffffffffu;
    seL4_Fault_ptr->words[5] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_LookupFailureType(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_LookupFailureType(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[4] &= ~0xffffffffu;
    seL4_Fault.words[4] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_LookupFailureType(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_LookupFailureType(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[4] &= ~0xffffffffu;
    seL4_Fault_ptr->words[4] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_MR4(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_MR4(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[3] &= ~0xffffffffu;
    seL4_Fault.words[3] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_MR4(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_MR4(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[3] &= ~0xffffffffu;
    seL4_Fault_ptr->words[3] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_MR5(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_MR5(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[2] &= ~0xffffffffu;
    seL4_Fault.words[2] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_MR5(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_MR5(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[2] &= ~0xffffffffu;
    seL4_Fault_ptr->words[2] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_CapFault_get_MR6(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault.words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_CapFault_set_MR6(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[1] &= ~0xffffffffu;
    seL4_Fault.words[1] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_CapFault_ptr_get_MR6(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    ret = (seL4_Fault_ptr->words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_CapFault_ptr_set_MR6(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_CapFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[1] &= ~0xffffffffu;
    seL4_Fault_ptr->words[1] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_new(seL4_Uint32 R0, seL4_Uint32 R1, seL4_Uint32 R2, seL4_Uint32 R3, seL4_Uint32 R4, seL4_Uint32 R5, seL4_Uint32 R6, seL4_Uint32 R7, seL4_Uint32 FaultIP, seL4_Uint32 SP, seL4_Uint32 LR, seL4_Uint32 CPSR, seL4_Uint32 Syscall) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_UnknownSyscall & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_UnknownSyscall & (1u << 31))) ? 0x0 : 0));

    seL4_Fault.words[0] = 0
        | ((seL4_Uint32)seL4_Fault_UnknownSyscall & 0x7u) << 0;
    seL4_Fault.words[1] = 0
        | Syscall << 0;
    seL4_Fault.words[2] = 0
        | CPSR << 0;
    seL4_Fault.words[3] = 0
        | LR << 0;
    seL4_Fault.words[4] = 0
        | SP << 0;
    seL4_Fault.words[5] = 0
        | FaultIP << 0;
    seL4_Fault.words[6] = 0
        | R7 << 0;
    seL4_Fault.words[7] = 0
        | R6 << 0;
    seL4_Fault.words[8] = 0
        | R5 << 0;
    seL4_Fault.words[9] = 0
        | R4 << 0;
    seL4_Fault.words[10] = 0
        | R3 << 0;
    seL4_Fault.words[11] = 0
        | R2 << 0;
    seL4_Fault.words[12] = 0
        | R1 << 0;
    seL4_Fault.words[13] = 0
        | R0 << 0;

    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_new(seL4_Fault_t *seL4_Fault_ptr, seL4_Uint32 R0, seL4_Uint32 R1, seL4_Uint32 R2, seL4_Uint32 R3, seL4_Uint32 R4, seL4_Uint32 R5, seL4_Uint32 R6, seL4_Uint32 R7, seL4_Uint32 FaultIP, seL4_Uint32 SP, seL4_Uint32 LR, seL4_Uint32 CPSR, seL4_Uint32 Syscall) {
    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_UnknownSyscall & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_UnknownSyscall & (1u << 31))) ? 0x0 : 0));

    seL4_Fault_ptr->words[0] = 0
        | ((seL4_Uint32)seL4_Fault_UnknownSyscall & 0x7u) << 0;
    seL4_Fault_ptr->words[1] = 0
        | Syscall << 0;
    seL4_Fault_ptr->words[2] = 0
        | CPSR << 0;
    seL4_Fault_ptr->words[3] = 0
        | LR << 0;
    seL4_Fault_ptr->words[4] = 0
        | SP << 0;
    seL4_Fault_ptr->words[5] = 0
        | FaultIP << 0;
    seL4_Fault_ptr->words[6] = 0
        | R7 << 0;
    seL4_Fault_ptr->words[7] = 0
        | R6 << 0;
    seL4_Fault_ptr->words[8] = 0
        | R5 << 0;
    seL4_Fault_ptr->words[9] = 0
        | R4 << 0;
    seL4_Fault_ptr->words[10] = 0
        | R3 << 0;
    seL4_Fault_ptr->words[11] = 0
        | R2 << 0;
    seL4_Fault_ptr->words[12] = 0
        | R1 << 0;
    seL4_Fault_ptr->words[13] = 0
        | R0 << 0;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R0(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[13] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R0(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[13] &= ~0xffffffffu;
    seL4_Fault.words[13] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R0(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[13] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R0(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[13] &= ~0xffffffffu;
    seL4_Fault_ptr->words[13] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R1(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[12] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R1(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[12] &= ~0xffffffffu;
    seL4_Fault.words[12] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R1(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[12] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R1(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[12] &= ~0xffffffffu;
    seL4_Fault_ptr->words[12] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R2(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[11] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R2(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[11] &= ~0xffffffffu;
    seL4_Fault.words[11] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R2(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[11] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R2(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[11] &= ~0xffffffffu;
    seL4_Fault_ptr->words[11] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R3(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[10] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R3(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[10] &= ~0xffffffffu;
    seL4_Fault.words[10] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R3(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[10] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R3(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[10] &= ~0xffffffffu;
    seL4_Fault_ptr->words[10] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R4(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[9] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R4(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[9] &= ~0xffffffffu;
    seL4_Fault.words[9] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R4(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[9] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R4(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[9] &= ~0xffffffffu;
    seL4_Fault_ptr->words[9] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R5(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[8] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R5(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[8] &= ~0xffffffffu;
    seL4_Fault.words[8] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R5(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[8] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R5(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[8] &= ~0xffffffffu;
    seL4_Fault_ptr->words[8] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R6(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[7] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R6(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[7] &= ~0xffffffffu;
    seL4_Fault.words[7] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R6(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[7] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R6(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[7] &= ~0xffffffffu;
    seL4_Fault_ptr->words[7] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_R7(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[6] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_R7(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[6] &= ~0xffffffffu;
    seL4_Fault.words[6] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_R7(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[6] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_R7(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[6] &= ~0xffffffffu;
    seL4_Fault_ptr->words[6] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_FaultIP(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[5] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_FaultIP(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[5] &= ~0xffffffffu;
    seL4_Fault.words[5] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_FaultIP(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[5] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_FaultIP(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[5] &= ~0xffffffffu;
    seL4_Fault_ptr->words[5] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_SP(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_SP(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[4] &= ~0xffffffffu;
    seL4_Fault.words[4] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_SP(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_SP(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[4] &= ~0xffffffffu;
    seL4_Fault_ptr->words[4] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_LR(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_LR(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[3] &= ~0xffffffffu;
    seL4_Fault.words[3] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_LR(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_LR(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[3] &= ~0xffffffffu;
    seL4_Fault_ptr->words[3] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_CPSR(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_CPSR(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[2] &= ~0xffffffffu;
    seL4_Fault.words[2] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_CPSR(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_CPSR(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[2] &= ~0xffffffffu;
    seL4_Fault_ptr->words[2] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UnknownSyscall_get_Syscall(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault.words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UnknownSyscall_set_Syscall(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[1] &= ~0xffffffffu;
    seL4_Fault.words[1] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UnknownSyscall_ptr_get_Syscall(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    ret = (seL4_Fault_ptr->words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UnknownSyscall_ptr_set_Syscall(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UnknownSyscall);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[1] &= ~0xffffffffu;
    seL4_Fault_ptr->words[1] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UserException_new(seL4_Uint32 FaultIP, seL4_Uint32 Stack, seL4_Uint32 CPSR, seL4_Uint32 Number, seL4_Uint32 Code) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_UserException & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_UserException & (1u << 31))) ? 0x0 : 0));

    seL4_Fault.words[0] = 0
        | ((seL4_Uint32)seL4_Fault_UserException & 0x7u) << 0;
    seL4_Fault.words[1] = 0
        | Code << 0;
    seL4_Fault.words[2] = 0
        | Number << 0;
    seL4_Fault.words[3] = 0
        | CPSR << 0;
    seL4_Fault.words[4] = 0
        | Stack << 0;
    seL4_Fault.words[5] = 0
        | FaultIP << 0;
    seL4_Fault.words[6] = 0;
    seL4_Fault.words[7] = 0;
    seL4_Fault.words[8] = 0;
    seL4_Fault.words[9] = 0;
    seL4_Fault.words[10] = 0;
    seL4_Fault.words[11] = 0;
    seL4_Fault.words[12] = 0;
    seL4_Fault.words[13] = 0;

    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UserException_ptr_new(seL4_Fault_t *seL4_Fault_ptr, seL4_Uint32 FaultIP, seL4_Uint32 Stack, seL4_Uint32 CPSR, seL4_Uint32 Number, seL4_Uint32 Code) {
    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_UserException & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_UserException & (1u << 31))) ? 0x0 : 0));

    seL4_Fault_ptr->words[0] = 0
        | ((seL4_Uint32)seL4_Fault_UserException & 0x7u) << 0;
    seL4_Fault_ptr->words[1] = 0
        | Code << 0;
    seL4_Fault_ptr->words[2] = 0
        | Number << 0;
    seL4_Fault_ptr->words[3] = 0
        | CPSR << 0;
    seL4_Fault_ptr->words[4] = 0
        | Stack << 0;
    seL4_Fault_ptr->words[5] = 0
        | FaultIP << 0;
    seL4_Fault_ptr->words[6] = 0;
    seL4_Fault_ptr->words[7] = 0;
    seL4_Fault_ptr->words[8] = 0;
    seL4_Fault_ptr->words[9] = 0;
    seL4_Fault_ptr->words[10] = 0;
    seL4_Fault_ptr->words[11] = 0;
    seL4_Fault_ptr->words[12] = 0;
    seL4_Fault_ptr->words[13] = 0;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UserException_get_FaultIP(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault.words[5] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UserException_set_FaultIP(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[5] &= ~0xffffffffu;
    seL4_Fault.words[5] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UserException_ptr_get_FaultIP(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault_ptr->words[5] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UserException_ptr_set_FaultIP(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[5] &= ~0xffffffffu;
    seL4_Fault_ptr->words[5] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UserException_get_Stack(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault.words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UserException_set_Stack(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[4] &= ~0xffffffffu;
    seL4_Fault.words[4] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UserException_ptr_get_Stack(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault_ptr->words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UserException_ptr_set_Stack(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[4] &= ~0xffffffffu;
    seL4_Fault_ptr->words[4] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UserException_get_CPSR(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault.words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UserException_set_CPSR(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[3] &= ~0xffffffffu;
    seL4_Fault.words[3] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UserException_ptr_get_CPSR(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault_ptr->words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UserException_ptr_set_CPSR(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[3] &= ~0xffffffffu;
    seL4_Fault_ptr->words[3] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UserException_get_Number(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault.words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UserException_set_Number(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[2] &= ~0xffffffffu;
    seL4_Fault.words[2] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UserException_ptr_get_Number(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault_ptr->words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UserException_ptr_set_Number(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[2] &= ~0xffffffffu;
    seL4_Fault_ptr->words[2] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_UserException_get_Code(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault.words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_UserException_set_Code(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[1] &= ~0xffffffffu;
    seL4_Fault.words[1] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_UserException_ptr_get_Code(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    ret = (seL4_Fault_ptr->words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_UserException_ptr_set_Code(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_UserException);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[1] &= ~0xffffffffu;
    seL4_Fault_ptr->words[1] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_VMFault_new(seL4_Uint32 IP, seL4_Uint32 Addr, seL4_Uint32 PrefetchFault, seL4_Uint32 FSR) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_VMFault & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_VMFault & (1u << 31))) ? 0x0 : 0));

    seL4_Fault.words[0] = 0
        | ((seL4_Uint32)seL4_Fault_VMFault & 0x7u) << 0;
    seL4_Fault.words[1] = 0
        | FSR << 0;
    seL4_Fault.words[2] = 0
        | PrefetchFault << 0;
    seL4_Fault.words[3] = 0
        | Addr << 0;
    seL4_Fault.words[4] = 0
        | IP << 0;
    seL4_Fault.words[5] = 0;
    seL4_Fault.words[6] = 0;
    seL4_Fault.words[7] = 0;
    seL4_Fault.words[8] = 0;
    seL4_Fault.words[9] = 0;
    seL4_Fault.words[10] = 0;
    seL4_Fault.words[11] = 0;
    seL4_Fault.words[12] = 0;
    seL4_Fault.words[13] = 0;

    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_VMFault_ptr_new(seL4_Fault_t *seL4_Fault_ptr, seL4_Uint32 IP, seL4_Uint32 Addr, seL4_Uint32 PrefetchFault, seL4_Uint32 FSR) {
    /* fail if user has passed bits that we will override */  
    seL4_DebugAssert(((seL4_Uint32)seL4_Fault_VMFault & ~0x7u) == ((0 && ((seL4_Uint32)seL4_Fault_VMFault & (1u << 31))) ? 0x0 : 0));

    seL4_Fault_ptr->words[0] = 0
        | ((seL4_Uint32)seL4_Fault_VMFault & 0x7u) << 0;
    seL4_Fault_ptr->words[1] = 0
        | FSR << 0;
    seL4_Fault_ptr->words[2] = 0
        | PrefetchFault << 0;
    seL4_Fault_ptr->words[3] = 0
        | Addr << 0;
    seL4_Fault_ptr->words[4] = 0
        | IP << 0;
    seL4_Fault_ptr->words[5] = 0;
    seL4_Fault_ptr->words[6] = 0;
    seL4_Fault_ptr->words[7] = 0;
    seL4_Fault_ptr->words[8] = 0;
    seL4_Fault_ptr->words[9] = 0;
    seL4_Fault_ptr->words[10] = 0;
    seL4_Fault_ptr->words[11] = 0;
    seL4_Fault_ptr->words[12] = 0;
    seL4_Fault_ptr->words[13] = 0;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_VMFault_get_IP(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault.words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_VMFault_set_IP(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[4] &= ~0xffffffffu;
    seL4_Fault.words[4] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_VMFault_ptr_get_IP(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault_ptr->words[4] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_VMFault_ptr_set_IP(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[4] &= ~0xffffffffu;
    seL4_Fault_ptr->words[4] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_VMFault_get_Addr(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault.words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_VMFault_set_Addr(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[3] &= ~0xffffffffu;
    seL4_Fault.words[3] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_VMFault_ptr_get_Addr(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault_ptr->words[3] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_VMFault_ptr_set_Addr(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[3] &= ~0xffffffffu;
    seL4_Fault_ptr->words[3] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_VMFault_get_PrefetchFault(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault.words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_VMFault_set_PrefetchFault(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[2] &= ~0xffffffffu;
    seL4_Fault.words[2] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_VMFault_ptr_get_PrefetchFault(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault_ptr->words[2] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_VMFault_ptr_set_PrefetchFault(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[2] &= ~0xffffffffu;
    seL4_Fault_ptr->words[2] |= (v32 << 0) & 0xffffffffu;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 CONST
seL4_Fault_VMFault_get_FSR(seL4_Fault_t seL4_Fault) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault.words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC seL4_Fault_t CONST
seL4_Fault_VMFault_set_FSR(seL4_Fault_t seL4_Fault, seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault.words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);
    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0 ) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault.words[1] &= ~0xffffffffu;
    seL4_Fault.words[1] |= (v32 << 0) & 0xffffffffu;
    return seL4_Fault;
}

LIBSEL4_INLINE_FUNC seL4_Uint32 PURE
seL4_Fault_VMFault_ptr_get_FSR(seL4_Fault_t *seL4_Fault_ptr) {
    seL4_Uint32 ret;
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    ret = (seL4_Fault_ptr->words[1] & 0xffffffffu) >> 0;
    /* Possibly sign extend */
    if (0 && (ret & (1u << (31)))) {
        ret |= 0x0;
    }
    return ret;
}

LIBSEL4_INLINE_FUNC void
seL4_Fault_VMFault_ptr_set_FSR(seL4_Fault_t *seL4_Fault_ptr,
                                      seL4_Uint32 v32) {
    seL4_DebugAssert(((seL4_Fault_ptr->words[0] >> 0) & 0x7) ==
           seL4_Fault_VMFault);

    /* fail if user has passed bits that we will override */
    seL4_DebugAssert((((~0xffffffffu >> 0) | 0x0) & v32) == ((0 && (v32 & (1u << (31)))) ? 0x0 : 0));

    seL4_Fault_ptr->words[1] &= ~0xffffffffu;
    seL4_Fault_ptr->words[1] |= (v32 << 0) & 0xffffffffu;
}

#endif
