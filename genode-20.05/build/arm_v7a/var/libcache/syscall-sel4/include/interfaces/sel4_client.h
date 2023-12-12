
/*
 * Automatically generated system call stubs.
 */

#ifndef __LIBSEL4_SEL4_CLIENT_H
#define __LIBSEL4_SEL4_CLIENT_H

#include <autoconf.h>
#include <sel4/types.h>

/*
 * The following code generates a compile-time error if the system call
 * stub generator has an incorrect understanding of how large a type is.
 *
 * If you receive a compile-time error here, you will need to adjust
 * the type information in the stub generator.
 */
#define assert_size_correct(type, expected_bytes) \
        typedef unsigned long __type_##type##_size_incorrect[ \
                (sizeof(type) == expected_bytes) ? 1 : -1]

assert_size_correct(int, 4);
assert_size_correct(long, 4);
assert_size_correct(seL4_Uint8, 1);
assert_size_correct(seL4_Uint16, 2);
assert_size_correct(seL4_Uint32, 4);
assert_size_correct(seL4_Uint64, 8);
assert_size_correct(seL4_Word, 4);
assert_size_correct(seL4_Bool, 1);
assert_size_correct(seL4_CapRights_t, 4);
assert_size_correct(seL4_CPtr, 4);
assert_size_correct(seL4_CNode, 4);
assert_size_correct(seL4_IRQHandler, 4);
assert_size_correct(seL4_IRQControl, 4);
assert_size_correct(seL4_TCB, 4);
assert_size_correct(seL4_Untyped, 4);
assert_size_correct(seL4_DomainSet, 4);
assert_size_correct(seL4_ARM_VMAttributes, 4);
assert_size_correct(seL4_ARM_Page, 4);
assert_size_correct(seL4_ARM_PageTable, 4);
assert_size_correct(seL4_ARM_PageDirectory, 4);
assert_size_correct(seL4_ARM_ASIDControl, 4);
assert_size_correct(seL4_ARM_ASIDPool, 4);
assert_size_correct(seL4_ARM_VCPU, 4);
assert_size_correct(seL4_ARM_IOSpace, 4);
assert_size_correct(seL4_ARM_IOPageTable, 4);
assert_size_correct(seL4_UserContext, 68);

/*
 * Return types for generated methods.
 */
struct seL4_ARM_Page_GetAddress {
	int error;
	seL4_Word paddr;
};
typedef struct seL4_ARM_Page_GetAddress seL4_ARM_Page_GetAddress_t;

struct seL4_ARM_VCPU_ReadRegs {
	int error;
	seL4_Word value;
};
typedef struct seL4_ARM_VCPU_ReadRegs seL4_ARM_VCPU_ReadRegs_t;

struct seL4_TCB_GetBreakpoint {
	int error;
	seL4_Word vaddr;
	seL4_Word type;
	seL4_Word size;
	seL4_Word rw;
	seL4_Bool is_enabled;
};
typedef struct seL4_TCB_GetBreakpoint seL4_TCB_GetBreakpoint_t;

struct seL4_TCB_ConfigureSingleStepping {
	int error;
	seL4_Bool bp_was_consumed;
};
typedef struct seL4_TCB_ConfigureSingleStepping seL4_TCB_ConfigureSingleStepping_t;

/*
 * Generated stubs.
 */
/**
 * @xmlonly <manual name="Page Directory - Clean Data" label="aarch32_pd_clean"/> @endxmlonly
 * @brief @xmlonly Clean cached pages within a page directory @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service 
 * @param[in] start Start address 
 * @param[in] end End address 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_PageDirectory_Clean_Data(seL4_ARM_PageDirectory _service, seL4_Word start, seL4_Word end)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPDClean_Data, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start);
	seL4_SetMR(1, end);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page Directory - Invalidate Data" label="aarch32_pd_invalidate"/> @endxmlonly
 * @brief @xmlonly Invalidate cached pages within a page directory @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service 
 * @param[in] start Start address 
 * @param[in] end End address 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_PageDirectory_Invalidate_Data(seL4_ARM_PageDirectory _service, seL4_Word start, seL4_Word end)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPDInvalidate_Data, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start);
	seL4_SetMR(1, end);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page Directory - Clean and Invalidate Data" label="aarch32_pd_clean_invalidate"/> @endxmlonly
 * @brief @xmlonly Clean and invalidate cached pages within a page directory @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service 
 * @param[in] start Start address 
 * @param[in] end End address 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_PageDirectory_CleanInvalidate_Data(seL4_ARM_PageDirectory _service, seL4_Word start, seL4_Word end)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPDCleanInvalidate_Data, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start);
	seL4_SetMR(1, end);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page Directory - Unify Instruction" label="aarch32_pd_unify_instruction"/> @endxmlonly
 * @brief @xmlonly Clean and invalidate cached instruction pages to point of unification @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service 
 * @param[in] start Start address 
 * @param[in] end End address 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_PageDirectory_Unify_Instruction(seL4_ARM_PageDirectory _service, seL4_Word start, seL4_Word end)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPDUnify_Instruction, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start);
	seL4_SetMR(1, end);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page Table - Map" label="arm_pagetable_map"/> @endxmlonly
 * @brief @xmlonly Map a page table into an address space. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page table being operated on.
 * @param[in] pd Capability to the VSpace which will contain the mapping. 
 * @param[in] vaddr Virtual address to map the page into. 
 * @param[in] attr VM Attributes for the mapping. Possible values for this type are given
 * in  @xmlonly <autoref label="ch:vspace"/> @endxmlonly . 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_PageTable_Map(seL4_ARM_PageTable _service, seL4_CPtr pd, seL4_Word vaddr, seL4_ARM_VMAttributes attr)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageTableMap, 0, 1, 2);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, pd);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, vaddr);
	seL4_SetMR(1, attr);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page Table - Unmap" label="arm_pagetable_unmap"/> @endxmlonly
 * @brief @xmlonly Unmap a page table from its address space and zero it out. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page table being operated on.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_PageTable_Unmap(seL4_ARM_PageTable _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageTableUnmap, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#if defined(CONFIG_ARM_SMMU)
/**
 * @xmlonly <manual name="I/O Page Table - Map" label="arm_io_page_table_map"/> @endxmlonly
 * @param[in] _service 
 * @param[in] iospace  
 * @param[in] ioaddr  
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_IOPageTable_Map(seL4_ARM_IOPageTable _service, seL4_ARM_IOSpace iospace, seL4_Word ioaddr)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMIOPageTableMap, 0, 1, 1);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, iospace);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, ioaddr);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
#if defined(CONFIG_ARM_SMMU)
/**
 * @xmlonly <manual name="I/O Page Table - Unmap" label="arm_io_page_table_unmap"/> @endxmlonly
 * @param[in] _service 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_IOPageTable_Unmap(seL4_ARM_IOPageTable _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMIOPageTableUnmap, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
/**
 * @xmlonly <manual name="Page - Map" label="arm_page_map"/> @endxmlonly
 * @brief @xmlonly Map a page into an address space. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] pd Capability to the VSpace which will contain the mapping. 
 * @param[in] vaddr Virtual address to map the page into. 
 * @param[in] rights Rights for the mapping. Possible values for this type are given in  @xmlonly <autoref label="sec:cap_rights"/> @endxmlonly . 
 * @param[in] attr VM Attributes for the mapping. Possible values for this type are given in  @xmlonly <autoref label="ch:vspace"/> @endxmlonly . 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_Map(seL4_ARM_Page _service, seL4_CPtr pd, seL4_Word vaddr, seL4_CapRights_t rights, seL4_ARM_VMAttributes attr)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageMap, 0, 1, 3);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, pd);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, vaddr);
	seL4_SetMR(1, rights.words[0]);
	seL4_SetMR(2, attr);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page - Remap" label="arm_page_remap"/> @endxmlonly
 * @brief @xmlonly Remap a page. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] pd Capability to the VSpace which will contain the mapping. 
 * @param[in] rights Rights for the mapping. Possible values for this type are given in  @xmlonly <autoref label="sec:cap_rights"/> @endxmlonly . 
 * @param[in] attr VM Attributes for the mapping. Possible values for this type are given in  @xmlonly <autoref label="ch:vspace"/> @endxmlonly . 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_Remap(seL4_ARM_Page _service, seL4_CPtr pd, seL4_CapRights_t rights, seL4_ARM_VMAttributes attr)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageRemap, 0, 1, 2);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, pd);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, rights.words[0]);
	seL4_SetMR(1, attr);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page - Unmap" label="arm_page_unmap"/> @endxmlonly
 * @brief @xmlonly Unmap a page. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_Unmap(seL4_ARM_Page _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageUnmap, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#if defined(CONFIG_ARM_SMMU)
/**
 * @xmlonly <manual name="Page - Map I/O" label="arm_page_map_io"/> @endxmlonly
 * @brief @xmlonly  @endxmlonly
 * 
 * @xmlonly
 * 
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] iospace  
 * @param[in] rights  
 * @param[in] ioaddr  
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_MapIO(seL4_ARM_Page _service, seL4_ARM_IOSpace iospace, seL4_CapRights_t rights, seL4_Word ioaddr)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageMapIO, 0, 1, 2);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, iospace);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, rights.words[0]);
	seL4_SetMR(1, ioaddr);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
/**
 * @xmlonly <manual name="Page - Clean Data" label="arm_page_clean_data"/> @endxmlonly
 * @brief @xmlonly Cleans the data cache out to RAM. The start and end are relative to the page being serviced. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] start_offset The offset, relative to the start of the page inclusive. 
 * @param[in] end_offset The offset, relative to the start of the page exclusive. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_Clean_Data(seL4_ARM_Page _service, seL4_Word start_offset, seL4_Word end_offset)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageClean_Data, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start_offset);
	seL4_SetMR(1, end_offset);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page - Invalidate Data" label="arm_page_invalidate_data"/> @endxmlonly
 * @brief @xmlonly Invalidates the cache range within the given page. The start and end are relative to the page being serviced
 * and should be aligned to a cache line boundary where possible.
 * An additional clean is performed on the outer cache lines if the start and end are
 * not aligned, to clean out the bytes between the requested and the cache line boundary. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] start_offset The offset, relative to the start of the page inclusive. 
 * @param[in] end_offset The offset, relative to the start of the page exclusive. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_Invalidate_Data(seL4_ARM_Page _service, seL4_Word start_offset, seL4_Word end_offset)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageInvalidate_Data, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start_offset);
	seL4_SetMR(1, end_offset);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page - Clean and Invalidate Data" label="arm_page_clean_and_invalidate_data"/> @endxmlonly
 * @brief @xmlonly Clean and invalidates the cache range within the given page. The range will be flushed out to RAM.
 * The start and end are relative to the page being serviced. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] start_offset The offset, relative to the start of the page inclusive. 
 * @param[in] end_offset The offset, relative to the start of the page exclusive. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_CleanInvalidate_Data(seL4_ARM_Page _service, seL4_Word start_offset, seL4_Word end_offset)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageCleanInvalidate_Data, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start_offset);
	seL4_SetMR(1, end_offset);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page - Unify Instruction" label="arm_page_unify_instruction"/> @endxmlonly
 * @brief @xmlonly Unify Instruction Cache. Cleans data lines to point of unification, invalidate
 * corresponding instruction lines to point of unification, then invalidates branch
 * predictors. The start and end are relative to the page being
 * serviced. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @param[in] start_offset The offset, relative to the start of the page inclusive. 
 * @param[in] end_offset The offset, relative to the start of the page exclusive. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_Page_Unify_Instruction(seL4_ARM_Page _service, seL4_Word start_offset, seL4_Word end_offset)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageUnify_Instruction, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, start_offset);
	seL4_SetMR(1, end_offset);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Page - Get Address" label="arm_page_get_address"/> @endxmlonly
 * @brief @xmlonly Get the physical address of the underlying frame. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability to the page being operated on.
 * @return @xmlonly 
 *                 A <texttt text="seL4_ARM_Page_GetAddress_t"/> struct that contains a
 *                 <texttt text="seL4_Word paddr"/>, which holds the physical address of the page,
 *                 and <texttt text="int error"/>. See <autoref label="sec:errors"/> for a description
 *                 of the message register and tag contents upon error.
 *              @endxmlonly
 */
LIBSEL4_INLINE seL4_ARM_Page_GetAddress_t
seL4_ARM_Page_GetAddress(seL4_ARM_Page _service)
{
	seL4_ARM_Page_GetAddress_t result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageGetAddress, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result.error = seL4_MessageInfo_get_label(output_tag);

	/* Unmarshal result. */
	result.paddr = seL4_GetMR(0);
	return result;
}

/**
 * @xmlonly <manual name="ASID Control - Make Pool" label="arm_asid_control_make_pool"/> @endxmlonly
 * @brief @xmlonly Create an ASID Pool. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service The master ASIDControl capability being operated on.
 * @param[in] untyped Capability to an untyped memory object that will become the pool. Must be 4K bytes. 
 * @param[in] root CPTR to the CNode that forms the root of the destination CSpace. Must be at a depth of 32. 
 * @param[in] index CPTR to the destination slot. Resolved from the root of the destination CSpace. 
 * @param[in] depth Number of bits of index to resolve to find the destination slot. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_ASIDControl_MakePool(seL4_ARM_ASIDControl _service, seL4_Untyped untyped, seL4_CNode root, seL4_Word index, seL4_Uint8 depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMASIDControlMakePool, 0, 2, 2);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, untyped);
	seL4_SetCap(1, root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, index);
	seL4_SetMR(1, (depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="ASID Pool - Asid Pool Assign" label="arm_asidpool_assign"/> @endxmlonly
 * @brief @xmlonly Assign an ASID Pool. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="ch:vspace"/>.
 * @endxmlonly
 * 
 * @param[in] _service The ASID pool which is being assigned to. Must not be full. Each ASID pool can contain 1024 entries.
 * @param[in] vroot The page directory that is being assigned to an ASID pool. Must not already be assigned to an ASID pool. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_ASIDPool_Assign(seL4_ARM_ASIDPool _service, seL4_CPtr vroot)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMASIDPoolAssign, 0, 1, 0);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, vroot);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
/**
 * @xmlonly <manual name="VCPU - Set TCB" label="arm_vcpu_set_tcb"/> @endxmlonly
 * @brief @xmlonly Bind a TCB to a virtual CPU @endxmlonly
 * 
 * @xmlonly
 * There is a 1:1 relationship between a virtual CPU and a TCB. If either (or both) of them is
 * associated with another one, they will be dissociated, and then associated to the
 * ones called in this system calls.
 * @endxmlonly
 * 
 * @param[in] _service 
 * @param[in] tcb Capability to TCB to bind to a virtual CPU 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_VCPU_SetTCB(seL4_ARM_VCPU _service, seL4_TCB tcb)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMVCPUSetTCB, 0, 1, 0);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, tcb);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
/**
 * @xmlonly <manual name="VCPU - Inject IRQ" label="arm_vcpu_inject_irq"/> @endxmlonly
 * @brief @xmlonly Inject an IRQ to a virtual CPU @endxmlonly
 * @param[in] _service 
 * @param[in] virq Virtual IRQ ID 
 * @param[in] priority Priority of the IRQ to be injected 
 * @param[in] group IRQ group 
 * @param[in] index IRQ index 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_VCPU_InjectIRQ(seL4_ARM_VCPU _service, seL4_Uint16 virq, seL4_Uint8 priority, seL4_Uint8 group, seL4_Uint8 index)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMVCPUInjectIRQ, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (virq & 0xfffful) | ((priority & 0xfful) << 16) | ((group & 0xfful) << 24));
	seL4_SetMR(1, (index & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
/**
 * @xmlonly <manual name="VCPU - Read Registers" label="arm_vcpu_read_registers"/> @endxmlonly
 * @brief @xmlonly Read a virtual CPU register @endxmlonly
 * @param[in] _service 
 * @param[in] field Register to read from a VCPU 
 * @return @xmlonly @endxmlonly
 */
LIBSEL4_INLINE seL4_ARM_VCPU_ReadRegs_t
seL4_ARM_VCPU_ReadRegs(seL4_ARM_VCPU _service, seL4_Word field)
{
	seL4_ARM_VCPU_ReadRegs_t result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMVCPUReadReg, 0, 0, 1);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, field);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result.error = seL4_MessageInfo_get_label(output_tag);

	/* Unmarshal result. */
	result.value = seL4_GetMR(0);
	return result;
}

#endif
#if defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
/**
 * @xmlonly <manual name="VCPU - Write Registers" label="arm_vcpu_write_registers"/> @endxmlonly
 * @brief @xmlonly Write a virtual CPU register @endxmlonly
 * @param[in] _service 
 * @param[in] field Register ID to write to a VCPU 
 * @param[in] value Value to be written to the VCPU register 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_ARM_VCPU_WriteRegs(seL4_ARM_VCPU _service, seL4_Word field, seL4_Word value)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMVCPUWriteReg, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, field);
	seL4_SetMR(1, value);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
/**
 * @xmlonly <manual name="Untyped - Retype" label="untyped_retype"/> @endxmlonly
 * @brief @xmlonly Retype an untyped object @endxmlonly
 * 
 * @xmlonly
 * Given a capability, <texttt text="_service"/>, to an untyped object,
 * creates <texttt text="num_objects"/> of the requested type. Creates
 * <texttt text="num_objects"/> capabilities to the new objects starting
 * at <texttt text="node_offset"/> in the CNode specified by
 * <texttt text="root"/>, <texttt text="node_index"/>, and
 * <texttt text="node_depth"/>.
 * 
 * For variable-sized
 * kernel objects, the <texttt text="size_bits"/> argument is used to
 * determine the size of objects to create. The relationship between
 * <texttt text="size_bits"/> and object size depends on the type of object
 * being created. See <autoref label="sec:object_sizes"/> for more information
 * about object sizes.
 * 
 * See <autoref label="sec:kernmemalloc"/> for more information about how untyped
 * memory is retyped.
 * 
 * See <autoref label="sec:caps_to_new_objects"/> for more information about the
 * placement of capabilities to created objects.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to an untyped object.
 * @param[in] type The seL4 object type that we are retyping to. 
 * @param[in] size_bits Used to determine the size of variable-sized objects. 
 * @param[in] root CPTR to the CNode at the root of the destination CSpace. 
 * @param[in] node_index CPTR to the destination CNode. Resolved relative to the root parameter. 
 * @param[in] node_depth Number of bits of node_index to translate when addressing the destination CNode. 
 * @param[in] node_offset Number of slots into the node at which capabilities start being placed. 
 * @param[in] num_objects Number of capabilities to create. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_Untyped_Retype(seL4_Untyped _service, seL4_Word type, seL4_Word size_bits, seL4_CNode root, seL4_Word node_index, seL4_Word node_depth, seL4_Word node_offset, seL4_Word num_objects)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(UntypedRetype, 0, 1, 6);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, type);
	seL4_SetMR(1, size_bits);
	seL4_SetMR(2, node_index);
	seL4_SetMR(3, node_depth);
	seL4_SetMR(4, node_offset);
	seL4_SetMR(5, num_objects);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Read Registers" label="tcb_readregisters"/> @endxmlonly
 * @brief @xmlonly Read a thread's registers into the first <texttt text="count"/> fields of a given
 * seL4_UserContext @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:read_write_registers"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] suspend_source The invocation should also suspend the source thread. 
 * @param[in] arch_flags Architecture dependent flags. These have no mearing on either x86 or ARM. 
 * @param[in] count The number of registers to read. 
 * @param[out] regs The structure to read the registers into. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_ReadRegisters(seL4_TCB _service, seL4_Bool suspend_source, seL4_Uint8 arch_flags, seL4_Word count, seL4_UserContext *regs)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBReadRegisters, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (suspend_source & 0x1ul) | ((arch_flags & 0xfful) << 8));
	seL4_SetMR(1, count);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	/* Unmarshal result. */
	regs->pc = seL4_GetMR(0);
	regs->sp = seL4_GetMR(1);
	regs->cpsr = seL4_GetMR(2);
	regs->r0 = seL4_GetMR(3);
	regs->r1 = seL4_GetMR(4);
	regs->r8 = seL4_GetMR(5);
	regs->r9 = seL4_GetMR(6);
	regs->r10 = seL4_GetMR(7);
	regs->r11 = seL4_GetMR(8);
	regs->r12 = seL4_GetMR(9);
	regs->r2 = seL4_GetMR(10);
	regs->r3 = seL4_GetMR(11);
	regs->r4 = seL4_GetMR(12);
	regs->r5 = seL4_GetMR(13);
	regs->r6 = seL4_GetMR(14);
	regs->r7 = seL4_GetMR(15);
	regs->r14 = seL4_GetMR(16);
	return result;
}

/**
 * @xmlonly <manual name="TCB - Write Registers" label="tcb_writeregisters"/> @endxmlonly
 * @brief @xmlonly Set a thread's registers to the first <texttt text="count"/> fields of a given seL4_UserContext @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:read_write_registers"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] resume_target The invocation should also resume the destination thread. 
 * @param[in] arch_flags Architecture dependent flags. These have no mearing on either x86 or ARM. 
 * @param[in] count The number of registers to be set. 
 * @param[in] regs Data structure containing the new register values. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_WriteRegisters(seL4_TCB _service, seL4_Bool resume_target, seL4_Uint8 arch_flags, seL4_Word count, seL4_UserContext *regs)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBWriteRegisters, 0, 0, 19);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (resume_target & 0x1ul) | ((arch_flags & 0xfful) << 8));
	seL4_SetMR(1, count);
	seL4_SetMR(2, regs->pc);
	seL4_SetMR(3, regs->sp);
	seL4_SetMR(4, regs->cpsr);
	seL4_SetMR(5, regs->r0);
	seL4_SetMR(6, regs->r1);
	seL4_SetMR(7, regs->r8);
	seL4_SetMR(8, regs->r9);
	seL4_SetMR(9, regs->r10);
	seL4_SetMR(10, regs->r11);
	seL4_SetMR(11, regs->r12);
	seL4_SetMR(12, regs->r2);
	seL4_SetMR(13, regs->r3);
	seL4_SetMR(14, regs->r4);
	seL4_SetMR(15, regs->r5);
	seL4_SetMR(16, regs->r6);
	seL4_SetMR(17, regs->r7);
	seL4_SetMR(18, regs->r14);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Copy Registers" label="tcb_copyregisters"/> @endxmlonly
 * @brief @xmlonly Copy the registers from one thread to another @endxmlonly
 * 
 * @xmlonly
 * In the context of this function, frame registers are those that are read, modified or preserved by a
 * system call and integer registers are those that are not. Refer to the seL4 userland library source for specifics.
 * <autoref label="sec:thread_deactivation"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on. This is the destination TCB.
 * @param[in] source Cap to the source TCB. 
 * @param[in] suspend_source The invocation should also suspend the source thread. 
 * @param[in] resume_target The invocation should also resume the destination thread. 
 * @param[in] transfer_frame Frame registers should be transferred. 
 * @param[in] transfer_integer Integer registers should be transferred. 
 * @param[in] arch_flags Architecture dependent flags. These have no mearing on either x86 or ARM. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_CopyRegisters(seL4_TCB _service, seL4_TCB source, seL4_Bool suspend_source, seL4_Bool resume_target, seL4_Bool transfer_frame, seL4_Bool transfer_integer, seL4_Uint8 arch_flags)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBCopyRegisters, 0, 1, 1);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, source);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (suspend_source & 0x1ul) | ((resume_target & 0x1ul) << 1) | ((transfer_frame & 0x1ul) << 2) | ((transfer_integer & 0x1ul) << 3) | ((arch_flags & 0xfful) << 8));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Configure" label="tcb_configure"/> @endxmlonly
 * @brief @xmlonly Set the parameters of a TCB @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:threads"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] fault_ep CPTR to the endpoint which receives IPCs when this thread faults. This capability is in the CSpace of the thread being configured. 
 * @param[in] cspace_root The new CSpace root. 
 * @param[in] cspace_root_data Optionally set the guard and guard size of the new root CNode. If set to zero, this parameter has no effect. 
 * @param[in] vspace_root The new VSpace root. 
 * @param[in] vspace_root_data Has no effect on x86 or ARM processors. 
 * @param[in] buffer Location of the thread's IPC buffer. Must be 512-byte aligned. The IPC buffer may not cross a page boundary. 
 * @param[in] bufferFrame Capability to a page containing the thread's IPC buffer. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_Configure(seL4_TCB _service, seL4_Word fault_ep, seL4_CNode cspace_root, seL4_Word cspace_root_data, seL4_CNode vspace_root, seL4_Word vspace_root_data, seL4_Word buffer, seL4_CPtr bufferFrame)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBConfigure, 0, 3, 4);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, cspace_root);
	seL4_SetCap(1, vspace_root);
	seL4_SetCap(2, bufferFrame);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, fault_ep);
	seL4_SetMR(1, cspace_root_data);
	seL4_SetMR(2, vspace_root_data);
	seL4_SetMR(3, buffer);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Set Priority" label="tcb_setpriority"/> @endxmlonly
 * @brief @xmlonly Change a thread's priority @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:sched"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] authority Capability to the TCB to use the MCP from when setting the priority. 
 * @param[in] priority The thread's new priority. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetPriority(seL4_TCB _service, seL4_CPtr authority, seL4_Word priority)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetPriority, 0, 1, 1);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, authority);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, priority);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Set Maximum Controlled Priority" label="tcb_setmcpriority"/> @endxmlonly
 * @brief @xmlonly Change a thread's maximum controlled priority @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:sched"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] authority Capability to the TCB to use the MCP from when setting the MCP. 
 * @param[in] mcp The thread's new maximum controlled priority. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetMCPriority(seL4_TCB _service, seL4_CPtr authority, seL4_Word mcp)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetMCPriority, 0, 1, 1);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, authority);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, mcp);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Set Sched Params" label="tcb_setschedparams"/> @endxmlonly
 * @brief @xmlonly Change a thread's priority and maximum controlled priority. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:sched"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] authority Capability to the TCB to use the MCP from when setting the priority and MCP. 
 * @param[in] mcp The thread's new maximum controlled priority. 
 * @param[in] priority The thread's new priority. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetSchedParams(seL4_TCB _service, seL4_CPtr authority, seL4_Word mcp, seL4_Word priority)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetSchedParams, 0, 1, 2);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, authority);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, mcp);
	seL4_SetMR(1, priority);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Set IPC Buffer" label="tcb_setipcbuffer"/> @endxmlonly
 * @brief @xmlonly Set a thread's IPC buffer @endxmlonly
 * 
 * @xmlonly
 * See Sections <shortref sec="threads"/> and <shortref sec="messageinfo"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] buffer Location of the thread's IPC buffer. Must be 512-byte aligned. The IPC buffer may not cross a page boundary. 
 * @param[in] bufferFrame Capability to a page containing the thread's IPC buffer. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetIPCBuffer(seL4_TCB _service, seL4_Word buffer, seL4_CPtr bufferFrame)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetIPCBuffer, 0, 1, 1);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, bufferFrame);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, buffer);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Set Space" label="tcb_setspace"/> @endxmlonly
 * @brief @xmlonly Set the fault endpoint, CSpace and VSpace of a thread @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:threads"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] fault_ep CPTR to the endpoint which receives IPCs when this thread faults. This capability is in the CSpace of the thread being configured. 
 * @param[in] cspace_root The new CSpace root. 
 * @param[in] cspace_root_data Optionally set the guard and guard size of the new root CNode. If set to zero, this parameter has no effect. 
 * @param[in] vspace_root The new VSpace root. 
 * @param[in] vspace_root_data Has no effect on x86 or ARM processors. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetSpace(seL4_TCB _service, seL4_Word fault_ep, seL4_CNode cspace_root, seL4_Word cspace_root_data, seL4_CNode vspace_root, seL4_Word vspace_root_data)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetSpace, 0, 2, 3);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, cspace_root);
	seL4_SetCap(1, vspace_root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, fault_ep);
	seL4_SetMR(1, cspace_root_data);
	seL4_SetMR(2, vspace_root_data);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Suspend" label="tcb_suspend"/> @endxmlonly
 * @brief @xmlonly Suspend a thread @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:thread_deactivation"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_Suspend(seL4_TCB _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSuspend, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Resume" label="tcb_resume"/> @endxmlonly
 * @brief @xmlonly Resume a thread @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:thread_deactivation"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_Resume(seL4_TCB _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBResume, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Bind Notification" label="tcb_bindnotification"/> @endxmlonly
 * @brief @xmlonly Binds a notification object to a <obj name="TCB"/> @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:notification-binding"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] notification Notification to bind. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_BindNotification(seL4_TCB _service, seL4_CPtr notification)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBBindNotification, 0, 1, 0);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, notification);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="TCB - Unbind Notification" label="tcb_unbindnotification"/> @endxmlonly
 * @brief @xmlonly Unbinds any notification object from a <obj name="TCB"/> @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:notification-binding"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_UnbindNotification(seL4_TCB _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBUnbindNotification, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#if CONFIG_MAX_NUM_NODES > 1
/**
 * @xmlonly <manual name="TCB - Set CPU Affinity" label="tcb_setaffinity"/> @endxmlonly
 * @brief @xmlonly Change a thread's current CPU in multicore machine @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:thread_creation"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] affinity The thread's new CPU to run. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetAffinity(seL4_TCB _service, seL4_Word affinity)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetAffinity, 0, 0, 1);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, affinity);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
#if defined(CONFIG_HARDWARE_DEBUG_API)
/**
 * @xmlonly <manual name="TCB - Set Breakpoint" label="tcb_setbreakpoint"/> @endxmlonly
 * @brief @xmlonly Set or modify a thread's breakpoints or watchpoints. Calls to this function
 * overwrite previous configurations for the target breakpoint. Do not use this
 * with seL4_SingleStep: the API will reject the call and return an error.
 * Instead, use seL4_TCB_ConfigureSingleStepping to configure single-stepping. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:debug_exceptions"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] bp_num The API-ID of a target breakpoint. This ID will be a positive integer, with values ranging from 0 to seL4_NumHWBreakpoints - 1. 
 * @param[in] vaddr A virtual address which forms part of the match conditions for the triggering of the breakpoint. 
 * @param[in] type One of: seL4_InstructionBreakpoint, which specifies that the breakpoint should occur on instruction execution at the specified vaddr or seL4_DataBreakpoint, which states that the breakpoint should occur on data access at the specified vaddr. 
 * @param[in] size A positive integer indicating the trigger-span of the watchpoint. Must be zero when 'type' is seL4_InstructionBreakpoint. 
 * @param[in] rw One of seL4_BreakOnRead, meaning the breakpoint will only be triggered on read-access; seL4_BreakOnWrite meaning the breakpoint will only be triggered on write-access, and seL4_BreakOnReadWrite meaning the breakpoint will be triggered on any access. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_SetBreakpoint(seL4_TCB _service, seL4_Uint16 bp_num, seL4_Word vaddr, seL4_Word type, seL4_Word size, seL4_Word rw)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetBreakpoint, 0, 0, 5);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (bp_num & 0xfffful));
	seL4_SetMR(1, vaddr);
	seL4_SetMR(2, type);
	seL4_SetMR(3, size);
	seL4_SetMR(4, rw);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
#if defined(CONFIG_HARDWARE_DEBUG_API)
/**
 * @xmlonly <manual name="TCB - Get Breakpoint" label="tcb_getbreakpoint"/> @endxmlonly
 * @brief @xmlonly Read a breakpoint or watchpoint's current configuration. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:debug_exceptions"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] bp_num The API-ID of a target breakpoint. This ID will be a positive integer, with values ranging from 0 to seL4_NumHWBreakpoints - 1. 
 * @return @xmlonly 
 *                 A <texttt text="seL4_TCB_GetBreakpoint_t"/>: Struct that contains
 *                 `<texttt text="seL4_Error error"/>', an seL4 API error value,
 *                 `<texttt text="seL4_Word vaddr"/>', the virtual address at which the breakpoint will currently
 *                 be triggered;
 *                 `<texttt text="seL4_Word type"/>', the type of operation which will currently trigger the
 *                 breakpoint, whether instruction execution, or data access;
 *                 `<texttt text="seL4_Word size"/>', integer value for the span-size of the breakpoint.
 *                 Usually a power of two (1, 2, 4, etc.);
 *                 `<texttt text="seL4_Word rw"/>', the access direction that will currently trigger the breakpoint,
 *                 whether read, write, or both and
 *                 `<texttt text="seL4_Bool is_enabled"/>', which indicates whether or not the breakpoint
 *                 will currently be triggered if the match conditions are met.
 *              @endxmlonly
 */
LIBSEL4_INLINE seL4_TCB_GetBreakpoint_t
seL4_TCB_GetBreakpoint(seL4_TCB _service, seL4_Uint16 bp_num)
{
	seL4_TCB_GetBreakpoint_t result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBGetBreakpoint, 0, 0, 1);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (bp_num & 0xfffful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result.error = seL4_MessageInfo_get_label(output_tag);

	/* Unmarshal result. */
	result.vaddr = seL4_GetMR(0);
	result.type = seL4_GetMR(1);
	result.size = seL4_GetMR(2);
	result.rw = seL4_GetMR(3);
	result.is_enabled = (seL4_GetMR(4) & 0x1);
	return result;
}

#endif
#if defined(CONFIG_HARDWARE_DEBUG_API)
/**
 * @xmlonly <manual name="TCB - Unset Breakpoint" label="tcb_unsetbreakpoint"/> @endxmlonly
 * @brief @xmlonly Disables a hardware breakpoint or watchpoint. The caller should assume that
 * the underlying configuration of the hardware registers has also been cleared.
 * Do not use this to clear single-stepping: the API will reject the call and
 * return an error. Instead, use seL4_TCB_ConfigureSingleStepping to disable
 * single-stepping. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:debug_exceptions"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] bp_num The API-ID of a target breakpoint. This ID will be a positive integer, with values ranging from 0 to seL4_NumHWBreakpoints - 1. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_TCB_UnsetBreakpoint(seL4_TCB _service, seL4_Uint16 bp_num)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBUnsetBreakpoint, 0, 0, 1);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (bp_num & 0xfffful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif
#if defined(CONFIG_HARDWARE_DEBUG_API)
/**
 * @xmlonly <manual name="TCB - Configure Single Stepping" label="tcb_configuresinglestepping"/> @endxmlonly
 * @brief @xmlonly Set or modify single stepping options for the target TCB. Subsequent calls to this
 * function overwrite previous configuration. Depending on your processor architecture,
 * this may or may not require the consumption of a hardware register. @endxmlonly
 * 
 * @xmlonly
 * See Sections <shortref sec="single_stepping_debug_exception"/> and <shortref sec="debug_exceptions"/>
 * @endxmlonly
 * 
 * @param[in] _service Capability to the TCB which is being operated on.
 * @param[in] bp_num The API-ID of a target breakpoint. This ID will be a positive integer, with values ranging from 0 to seL4_NumHWBreakpoints - 1. 
 * @param[in] num_instructions Number of instructions to step over before delivering a fault to the target thread's fault endpoint. Setting this to 0 disables single-stepping. 
 * @return @xmlonly 
 *                 A <texttt text="seL4_TCB_ConfigureSingleStepping_t"/>: Struct that contains
 *                 `<texttt text="seL4_Error error"/>', an seL4 API error value,
 *                 `<texttt text="seL4_Bool bp_was_consumed"/>', a boolean which indicates whether or not the <texttt text="bp_num"/>
 *                 breakpoint ID that was passed to the function, was consumed in the setup of the single-stepping
 *                 functionality: if this is <texttt text="true"/>, the caller should not attempt to re-use <texttt text="bp_num"/>
 *                 until it has disabled the single-stepping functionality via a subsequent call to
 *                 seL4_TCB_ConfigureSingleStepping with an <texttt text="num_instructions"/> argument of 0.
 *              @endxmlonly
 */
LIBSEL4_INLINE seL4_TCB_ConfigureSingleStepping_t
seL4_TCB_ConfigureSingleStepping(seL4_TCB _service, seL4_Uint16 bp_num, seL4_Word num_instructions)
{
	seL4_TCB_ConfigureSingleStepping_t result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBConfigureSingleStepping, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (bp_num & 0xfffful));
	seL4_SetMR(1, num_instructions);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result.error = seL4_MessageInfo_get_label(output_tag);

	/* Unmarshal result. */
	result.bp_was_consumed = (seL4_GetMR(0) & 0x1);
	return result;
}

#endif
/**
 * @xmlonly <manual name="CNode - Revoke" label="cnode_revoke"/> @endxmlonly
 * @brief @xmlonly Delete all child capabilities of a capability @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode at the root of the CSpace where the capability will be found. Must be at a depth of 32.
 * @param[in] index CPTR to the capability. Resolved from the root of the _service parameter. 
 * @param[in] depth Number of bits of index to resolve to find the capability being operated on. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Revoke(seL4_CNode _service, seL4_Word index, seL4_Uint8 depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeRevoke, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, index);
	seL4_SetMR(1, (depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Delete" label="cnode_delete"/> @endxmlonly
 * @brief @xmlonly Delete a capability @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode at the root of the CSpace where the capability will be found. Must be at a depth of 32.
 * @param[in] index CPTR to the capability. Resolved from the root of the _service parameter. 
 * @param[in] depth Number of bits of index to resolve to find the capability being operated on. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Delete(seL4_CNode _service, seL4_Word index, seL4_Uint8 depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeDelete, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, index);
	seL4_SetMR(1, (depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Cancel Badged Sends" label="cnode_cancelbadgedsends"/> @endxmlonly
 * @brief @xmlonly The cancel badged sends method is intend to allow for the reuse of badges by an
 * authority. When used with a badged endpoint capability it
 * will cancel any outstanding send operations for that endpoint and badge.
 * This operation has no effect on un-badged or other objects. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode at the root of the CSpace where the capability will be found. Must be at a depth of 32.
 * @param[in] index CPTR to the capability. Resolved from the root of the _service parameter. 
 * @param[in] depth Number of bits of index to resolve to find the capability being operated on. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_CancelBadgedSends(seL4_CNode _service, seL4_Word index, seL4_Uint8 depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeCancelBadgedSends, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, index);
	seL4_SetMR(1, (depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Copy" label="cnode_copy"/> @endxmlonly
 * @brief @xmlonly Copy a capability, setting its access rights whilst doing so @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode that forms the root of the destination CSpace. Must be at a depth of 32.
 * @param[in] dest_index CPTR to the destination slot. Resolved from the root of the destination CSpace. 
 * @param[in] dest_depth Number of bits of dest_index to resolve to find the destination slot. 
 * @param[in] src_root CPTR to the CNode that forms the root of the source CSpace. Must be at a depth of 32. 
 * @param[in] src_index CPTR to the source slot. Resolved from the root of the source CSpace. 
 * @param[in] src_depth Number of bits of src_index to resolve to find the source slot. 
 * @param[in] rights The rights inherited by the new capability. Possible values for this type are given in  @xmlonly <autoref label="sec:cap_rights"/> @endxmlonly . 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Copy(seL4_CNode _service, seL4_Word dest_index, seL4_Uint8 dest_depth, seL4_CNode src_root, seL4_Word src_index, seL4_Uint8 src_depth, seL4_CapRights_t rights)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeCopy, 0, 1, 5);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, dest_index);
	seL4_SetMR(1, (dest_depth & 0xfful));
	seL4_SetMR(2, src_index);
	seL4_SetMR(3, (src_depth & 0xfful));
	seL4_SetMR(4, rights.words[0]);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Mint" label="cnode_mint"/> @endxmlonly
 * @brief @xmlonly Copy a capability, setting its access rights and badge whilst doing so @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode that forms the root of the destination CSpace. Must be at a depth of 32.
 * @param[in] dest_index CPTR to the destination slot. Resolved from the root of the destination CSpace. 
 * @param[in] dest_depth Number of bits of dest_index to resolve to find the destination slot. 
 * @param[in] src_root CPTR to the CNode that forms the root of the source CSpace. Must be at a depth of 32. 
 * @param[in] src_index CPTR to the source slot. Resolved from the root of the source CSpace. 
 * @param[in] src_depth Number of bits of src_index to resolve to find the source slot. 
 * @param[in] rights The rights inherited by the new capability. Possible values for this type are given in  @xmlonly <autoref label="sec:cap_rights"/> @endxmlonly . 
 * @param[in] badge Badge or guard to be applied to the new capability. For badges the high 4 bits are ignored. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Mint(seL4_CNode _service, seL4_Word dest_index, seL4_Uint8 dest_depth, seL4_CNode src_root, seL4_Word src_index, seL4_Uint8 src_depth, seL4_CapRights_t rights, seL4_Word badge)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeMint, 0, 1, 6);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, dest_index);
	seL4_SetMR(1, (dest_depth & 0xfful));
	seL4_SetMR(2, src_index);
	seL4_SetMR(3, (src_depth & 0xfful));
	seL4_SetMR(4, rights.words[0]);
	seL4_SetMR(5, badge);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Move" label="cnode_move"/> @endxmlonly
 * @brief @xmlonly Move a capability @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode that forms the root of the destination CSpace. Must be at a depth of 32.
 * @param[in] dest_index CPTR to the destination slot. Resolved from the root of the destination CSpace. 
 * @param[in] dest_depth Number of bits of dest_index to resolve to find the destination slot. 
 * @param[in] src_root CPTR to the CNode that forms the root of the source CSpace. Must be at a depth of 32. 
 * @param[in] src_index CPTR to the source slot. Resolved from the root of the source CSpace. 
 * @param[in] src_depth Number of bits of src_index to resolve to find the source slot. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Move(seL4_CNode _service, seL4_Word dest_index, seL4_Uint8 dest_depth, seL4_CNode src_root, seL4_Word src_index, seL4_Uint8 src_depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeMove, 0, 1, 4);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, dest_index);
	seL4_SetMR(1, (dest_depth & 0xfful));
	seL4_SetMR(2, src_index);
	seL4_SetMR(3, (src_depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Mutate" label="cnode_mutate"/> @endxmlonly
 * @brief @xmlonly Move a capability, setting its badge in the process @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode that forms the root of the destination CSpace. Must be at a depth of 32.
 * @param[in] dest_index CPTR to the destination slot. Resolved from the root of the destination CSpace. 
 * @param[in] dest_depth Number of bits of dest_index to resolve to find the destination slot. 
 * @param[in] src_root CPTR to the CNode that forms the root of the source CSpace. Must be at a depth of 32. 
 * @param[in] src_index CPTR to the source slot. Resolved from the root of the source CSpace. 
 * @param[in] src_depth Number of bits of src_index to resolve to find the source slot. 
 * @param[in] badge Badge or guard to be applied to the new capability. For badges the high 4 bits are ignored. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Mutate(seL4_CNode _service, seL4_Word dest_index, seL4_Uint8 dest_depth, seL4_CNode src_root, seL4_Word src_index, seL4_Uint8 src_depth, seL4_Word badge)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeMutate, 0, 1, 5);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, dest_index);
	seL4_SetMR(1, (dest_depth & 0xfful));
	seL4_SetMR(2, src_index);
	seL4_SetMR(3, (src_depth & 0xfful));
	seL4_SetMR(4, badge);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Rotate" label="cnode_rotate"/> @endxmlonly
 * @brief @xmlonly Given 3 capability slots - a destination, pivot and source - move the capability in the
 * pivot slot to the destination slot and the capability in the source slot to the pivot slot @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode at the root of the CSpace where the destination slot will be found. Must be at a depth of 32.
 * @param[in] dest_index CPTR to the destination slot. Resolved relative to _service. Must be empty unless it refers to the same slot as the source slot. 
 * @param[in] dest_depth Depth to resolve dest_index to. 
 * @param[in] dest_badge The new capdata for the capability that ends up in the destination slot. 
 * @param[in] pivot_root CPTR to the CNode at the root of the CSpace where the pivot slot will be found. Must be at a depth of 32. 
 * @param[in] pivot_index CPTR to the pivot slot. Resolved relative to pivot_root. The resolved slot must not refer to the source or destination slots. 
 * @param[in] pivot_depth Depth to resolve pivot_index to. 
 * @param[in] pivot_badge The new capdata for the capability that ends up in the pivot slot. 
 * @param[in] src_root CPTR to the CNode at the root of the CSpace where the source slot will be found. Must be at a depth of 32. 
 * @param[in] src_index CPTR to the source slot. Resolved relative to src_root. 
 * @param[in] src_depth Depth to resolve src_index to. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_Rotate(seL4_CNode _service, seL4_Word dest_index, seL4_Uint8 dest_depth, seL4_Word dest_badge, seL4_CNode pivot_root, seL4_Word pivot_index, seL4_Uint8 pivot_depth, seL4_Word pivot_badge, seL4_CNode src_root, seL4_Word src_index, seL4_Uint8 src_depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeRotate, 0, 2, 8);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, pivot_root);
	seL4_SetCap(1, src_root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, dest_index);
	seL4_SetMR(1, (dest_depth & 0xfful));
	seL4_SetMR(2, dest_badge);
	seL4_SetMR(3, pivot_index);
	seL4_SetMR(4, (pivot_depth & 0xfful));
	seL4_SetMR(5, pivot_badge);
	seL4_SetMR(6, src_index);
	seL4_SetMR(7, (src_depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="CNode - Save Caller" label="cnode_savecaller"/> @endxmlonly
 * @brief @xmlonly Save the reply capability from the last time the thread was called in the given CSpace so that it can be invoked later @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:cnode-ops"/>.
 * @endxmlonly
 * 
 * @param[in] _service CPTR to the CNode at the root of the CSpace where the capability is to be saved. Must be at a depth of 32.
 * @param[in] index CPTR to the slot in which to save the capability. Resolved from the root of the _service parameter. 
 * @param[in] depth Number of bits of index to resolve to find the slot being targeted. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_CNode_SaveCaller(seL4_CNode _service, seL4_Word index, seL4_Uint8 depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeSaveCaller, 0, 0, 2);
	seL4_MessageInfo_t output_tag;

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, index);
	seL4_SetMR(1, (depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="IRQ Control - Get" label="irq_controlget"/> @endxmlonly
 * @brief @xmlonly Create an IRQ handler capability @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:interrupts"/>.
 * @endxmlonly
 * 
 * @param[in] _service An IRQControl capability. This gives you the authority to make this call.
 * @param[in] irq The IRQ that you want this capability to handle. 
 * @param[in] root CPTR to the CNode that forms the root of the destination CSpace. Must be at a depth of 32. 
 * @param[in] index CPTR to the destination slot. Resolved from the root of the destination CSpace. 
 * @param[in] depth Number of bits of dest_index to resolve to find the destination slot. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_IRQControl_Get(seL4_IRQControl _service, int irq, seL4_CNode root, seL4_Word index, seL4_Uint8 depth)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQIssueIRQHandler, 0, 1, 3);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, root);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, irq);
	seL4_SetMR(1, index);
	seL4_SetMR(2, (depth & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="IRQ Handler - Acknowledge" label="irq_handleracknowledge"/> @endxmlonly
 * @brief @xmlonly Acknowledge the receipt of an interrupt and re-enable it @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:interrupts"/>.
 * @endxmlonly
 * 
 * @param[in] _service The IRQ handler capability.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_IRQHandler_Ack(seL4_IRQHandler _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQAckIRQ, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="IRQ Handler - Set Notification" label="irq_handlersetnotification"/> @endxmlonly
 * @brief @xmlonly Set the notification which the kernel will signal on interrupts
 * controlled by the supplied IRQ handler capability @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:interrupts"/>.
 * @endxmlonly
 * 
 * @param[in] _service The IRQ handler capability.
 * @param[in] notification The notification which the IRQs will signal. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_IRQHandler_SetNotification(seL4_IRQHandler _service, seL4_CPtr notification)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQSetIRQHandler, 0, 1, 0);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, notification);

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="IRQ Handler - Clear" label="irq_handlerclear"/> @endxmlonly
 * @brief @xmlonly Clear the handler capability from the IRQ slot @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:interrupts"/>.
 * @endxmlonly
 * 
 * @param[in] _service The IRQ handler capability.
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_IRQHandler_Clear(seL4_IRQHandler _service)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQClearIRQHandler, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

/**
 * @xmlonly <manual name="Domain Set - Set" label="domainset_set"/> @endxmlonly
 * @brief @xmlonly Change the domain of a thread. @endxmlonly
 * 
 * @xmlonly
 * See <autoref label="sec:domains"/>.
 * @endxmlonly
 * 
 * @param[in] _service Capability allowing domain configuration.
 * @param[in] domain The thread's new domain. 
 * @param[in] thread Capability to the TCB which is being operated on. 
 * @return @xmlonly <errorenumdesc/> @endxmlonly
 */
LIBSEL4_INLINE seL4_Error
seL4_DomainSet_Set(seL4_DomainSet _service, seL4_Uint8 domain, seL4_TCB thread)
{
	seL4_Error result;
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(DomainSetSet, 0, 1, 1);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, thread);

	/* Marshal and initialise parameters. */
	seL4_SetMR(0, (domain & 0xfful));

	/* Perform the call. */
	output_tag = seL4_Call(_service, tag);
	result = (seL4_Error) seL4_MessageInfo_get_label(output_tag);

	return result;
}

#endif /* __LIBSEL4_SEL4_CLIENT_H */
