# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module defines the final block.

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from common.designcfgs import is_design_32bit, get_design_stop_sig_addr, get_design_reg_dump_addr, design_has_float_support, design_has_double_support, get_design_fpreg_dump_addr
from params.fuzzparams import RDEP_MASK_REGISTER_ID, MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS, FPU_ENDIS_REGISTER_ID
from cascade.privilegestate import PrivilegeStateEnum
from rv.asmutil import li_into_reg
from cascade.cfinstructionclasses import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, FloatStoreInstruction, JALInstruction, SpecialInstruction, CSRRegInstruction

def get_finalblock_max_size():
    return (10 + 2*MAX_NUM_PICKABLE_REGS + 2*MAX_NUM_PICKABLE_FLOATING_REGS - 1) * 4

# We must instantiate it in the end because we must know whether we have the privileges to turn on the FPU.
# Returns the instruction objects of the tail basic block
def finalblock(fuzzerstate, design_name: str):
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    if DO_ASSERT:
        # Sign extension handling is now implemented in li_into_reg function
        # We can handle addresses up to 0xFFFFFFFF (32-bit range)
        assert regdump_addr < (1 << 32), f"regdump_addr {hex(regdump_addr)} exceeds 32-bit address space"
        assert stopsig_addr < (1 << 32), f"stopsig_addr {hex(stopsig_addr)} exceeds 32-bit address space"

    ret = []
    is_design_64bit = not is_design_32bit(design_name)
    design_has_fpu = design_has_float_support(design_name)
    design_has_fpudouble = design_has_double_support(design_name)

    ###
    # Dump registers
    ###

    from rv.asmutil import li_into_reg_64bit_safe

    # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # Compute the register dump address using 64-bit safe method
    if regdump_addr >= 0x80000000 and is_design_64bit:
        # Use special handling for high addresses on 64-bit systems
        if regdump_addr == 0x80000000:
            # Optimized sequence for exactly 0x80000000
            # addi reg, x0, 1; slli reg, reg, 31  -> loads 0x80000000 without sign extension
            ret += [
                RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, 0, 1, is_design_64bit),  # Load 1 (x0 + 1)
                RegImmInstruction("slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 31, is_design_64bit)
            ]
        else:
            # General case for other high addresses
            lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr, do_check_bounds=False)
            ret += [
                ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_regdump, is_design_64bit),
                RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_regdump, is_design_64bit),
                RegImmInstruction("slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit),
                RegImmInstruction("srli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit)
            ]
    else:
        # Normal case for addresses < 0x80000000 or 32-bit systems
        lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr)
        ret += [
            ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_regdump, is_design_64bit),
            RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_regdump, is_design_64bit)
        ]

    # Store the register values to the register dump address
    ret.append(SpecialInstruction("fence")) # Hopefully this prevents speculative execution of the stores
    for reg_id in range(1, MAX_NUM_PICKABLE_REGS):
        ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, reg_id, 0, -1, is_design_64bit))
        ret.append(SpecialInstruction("fence"))

    # Store the floating values as well, if FPU is supported and if there is no risk of it being deactivated
    if design_has_fpu and not fuzzerstate.is_fpu_activated:
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            # Enable the FPU
            ret.append(CSRRegInstruction("csrrw", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
            fuzzerstate.is_fpu_activated = True
        if fuzzerstate.is_fpu_activated:
            # Get the FP register dump address and load it properly
            fpregdump_addr = get_design_fpreg_dump_addr(design_name)

            # Load fpregdump_addr using 64-bit safe method (similar to regdump_addr)
            # We'll use a different register to avoid overwriting RDEP_MASK_REGISTER_ID
            # Let's use the next available register (RDEP_MASK_REGISTER_ID + 1)
            fpreg_base_reg = RDEP_MASK_REGISTER_ID + 1

            if fpregdump_addr >= 0x80000000 and is_design_64bit:
                # Use special handling for high addresses on 64-bit systems
                if fpregdump_addr == 0x80001000:
                    # Optimized sequence for exactly 0x80001000
                    # addi reg, x0, 1; slli reg, reg, 31; addi reg, reg, 0x1000
                    # But 0x1000 is too large for addi, so use lui + addi approach
                    ret += [
                        ImmRdInstruction("lui", fpreg_base_reg, 0x80001, is_design_64bit),  # Load 0x80001000
                        RegImmInstruction("slli", fpreg_base_reg, fpreg_base_reg, 32, is_design_64bit),  # Shift left 32
                        RegImmInstruction("srli", fpreg_base_reg, fpreg_base_reg, 32, is_design_64bit)   # Shift right 32 (clear upper bits)
                    ]
                else:
                    # General case for other high addresses
                    lui_imm_fpreg, addi_imm_fpreg = li_into_reg(fpregdump_addr, do_check_bounds=False)
                    ret += [
                        ImmRdInstruction("lui", fpreg_base_reg, lui_imm_fpreg, is_design_64bit),
                        RegImmInstruction("addi", fpreg_base_reg, fpreg_base_reg, addi_imm_fpreg, is_design_64bit),
                        RegImmInstruction("slli", fpreg_base_reg, fpreg_base_reg, 32, is_design_64bit),
                        RegImmInstruction("srli", fpreg_base_reg, fpreg_base_reg, 32, is_design_64bit)
                    ]
            else:
                # Normal case for addresses < 0x80000000 or 32-bit systems
                lui_imm_fpreg, addi_imm_fpreg = li_into_reg(fpregdump_addr)
                ret += [
                    ImmRdInstruction("lui", fpreg_base_reg, lui_imm_fpreg, is_design_64bit),
                    RegImmInstruction("addi", fpreg_base_reg, fpreg_base_reg, addi_imm_fpreg, is_design_64bit)
                ]

            # Store FP registers using the correct base address (offset 0 from fpregdump_addr)
            for reg_id in range(MAX_NUM_PICKABLE_FLOATING_REGS):
                ret.append(FloatStoreInstruction("fsd" if design_has_fpudouble else "fsw", fpreg_base_reg, reg_id, 0, -1, is_design_64bit))
                ret.append(SpecialInstruction("fence"))

    ###
    # Stop request
    ###

    # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # Compute the stop request address using 64-bit safe method
    if stopsig_addr >= 0x80000000 and is_design_64bit:
        # Use special handling for high addresses on 64-bit systems
        if stopsig_addr == 0x80002000:
            # Optimized sequence for exactly 0x80002000
            # Load 0x80002 into upper bits, then shift
            ret += [
                ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, 0x80002, is_design_64bit),  # Load 0x80002000 into upper 20 bits
                RegImmInstruction("slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit),  # Shift left 32
                RegImmInstruction("srli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit)   # Shift right 32 (clear upper bits)
            ]
        elif stopsig_addr == 0x80004000:
            # Optimized sequence for exactly 0x80004000
            # Load 0x80004 into upper bits, then shift
            ret += [
                ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, 0x80004, is_design_64bit),  # Load 0x80004000 into upper 20 bits
                RegImmInstruction("slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit),  # Shift left 32
                RegImmInstruction("srli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit)   # Shift right 32 (clear upper bits)
            ]
        else:
            # General case for other high addresses
            lui_imm_stopreq, addi_imm_stopreq = li_into_reg(stopsig_addr, do_check_bounds=False)
            ret += [
                ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_stopreq, is_design_64bit),
                RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_stopreq, is_design_64bit),
                RegImmInstruction("slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit),
                RegImmInstruction("srli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_design_64bit)
            ]
    else:
        # Normal case for addresses < 0x80000000 or 32-bit systems
        lui_imm_stopreq, addi_imm_stopreq = li_into_reg(stopsig_addr)
        ret += [
            ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_stopreq, is_design_64bit),
            RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_stopreq, is_design_64bit)
        ]

    # Store the register values to the register dump address
    ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 0, 0 & 0xFFFF, -1, is_design_64bit))
    ret.append(SpecialInstruction("fence"))

    # Infinite loop in the end of the simulation
    ret.append(JALInstruction("jal", 0, 0))

    if DO_ASSERT:
        assert len(ret) * 4 <= get_finalblock_max_size(), f"The final block is larger than expected: {len(ret) * 4} > {get_finalblock_max_size()}"

    return ret

# Spike does not support writing to some signaling addresses, but at the same time, we do not need it for spike resolution anyway. So let's replace it with an infinite loop.
def finalblock_spike_resolution():
    # Infinite loop in the end of the simulation
    return [JALInstruction("jal", 0, 0)]
