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
    stopsig_addr = get_design_stop_sig_addr(design_name)
    regdump_addr = get_design_reg_dump_addr(design_name)
    assert stopsig_addr == 0x60000000
    assert regdump_addr == 0x60000010

    ret = []
    is_design_64bit = not is_design_32bit(design_name)
    design_has_fpu = design_has_float_support(design_name)
    design_has_fpudouble = design_has_double_support(design_name)
    assert is_design_64bit is True
    assert design_has_fpu is True
    assert design_has_fpudouble is True

    ###
    # Dump registers
    ###

    # 80002d7c:   60000f37            lui     t5,0x60000
    # 80002d80:   010f0f13            addi    t5,t5,16 # 0x60000010

    lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr)
    assert lui_imm_regdump == 0x60000 and addi_imm_regdump == 0x010

    # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # Compute the register dump address
    assert RDEP_MASK_REGISTER_ID == 30  # x30 is t5
    ret += [
        ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_regdump, is_design_64bit),
        RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_regdump, is_design_64bit)
    ]

    # 80002d84:   0ff0000f            fence
    # 80002d88:   001f3023            sd  ra,0(t5)
    # 80002d8c:   0ff0000f            fence
    # ...
    # 80002e40:   018f3023            sd  s8,0(t5)
    # 80002e44:   0ff0000f            fence

    # Store the register values to the register dump address
    ret.append(SpecialInstruction("fence")) # Hopefully this prevents speculative execution of the stores
    assert MAX_NUM_PICKABLE_REGS == 25
    for reg_id in range(1, MAX_NUM_PICKABLE_REGS):
        ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, reg_id, 0, -1, is_design_64bit))
        ret.append(SpecialInstruction("fence"))

    # Store the floating values as well, if FPU is supported and if there is no risk of it being deactivated
    #assert fuzzerstate.is_fpu_activated is False
    if design_has_fpu and not fuzzerstate.is_fpu_activated:

        # XXX: it is defined in config
        # Check that the fpregdump addr is correctly positioned
        assert get_design_fpreg_dump_addr(design_name) == regdump_addr + 8, f"We make the assumption that the FP regdump addr is the int regdump address + 8. However, currently, they are respectively {hex(get_design_fpreg_dump_addr(design_name))} and regdump_addr={hex(regdump_addr)}"

        # 80002e48:   300e9073            csrrw   x0,mstatus,x29

        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            # Enable the FPU
            ret.append(CSRRegInstruction("csrrw", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
            fuzzerstate.is_fpu_activated = True

        # 80002e4c:   000f3427            fsd f0,8(x30)
        # 80002e50:   0ff0000f            fence   iorw,iorw
        # ...
        # 80002eb4:   00df3427            fsd f13,8(x30)
        # 80002eb8:   0ff0000f            fence   iorw,iorw

        if fuzzerstate.is_fpu_activated:
            for reg_id in range(MAX_NUM_PICKABLE_FLOATING_REGS):
                ret.append(FloatStoreInstruction("fsd" if design_has_fpudouble else "fsw", RDEP_MASK_REGISTER_ID, reg_id, 8, -1, is_design_64bit))
                ret.append(SpecialInstruction("fence"))

    ###
    # Stop request
    ###

    lui_imm_stopreq, addi_imm_stopreq = li_into_reg(stopsig_addr)
    assert lui_imm_stopreq == 0x60000 and addi_imm_stopreq == 0x000

    # 80002ebc:   60000f37            lui x30,0x60000
    # 80002ec0:   000f0f13            addi    x30,x30,0 # 0x60000000
    # 80002ec4:   000f3023            sd  x0,0(x30)
    # 80002ec8:   0ff0000f            fence   iorw,iorw
    # 80002ecc:   0000006f            jal x0,0x80002ecc

    # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # Compute the stop request address
    ret += [
        ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_stopreq, is_design_64bit),
        RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_stopreq, is_design_64bit)
    ]

    # Store the register values to the register dump address
    ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 0, 0 & 0xFFFF, -1, is_design_64bit))
    ret.append(SpecialInstruction("fence"))

    # Infinite loop in the end of the simulation
    ret.append(JALInstruction("jal", 0, 0))

    # XXX: seems like nothing register values dumped to memory correctly?

    assert len(ret) * 4 <= get_finalblock_max_size(), f"The final block is larger than expected: {len(ret) * 4} > {get_finalblock_max_size()}"
    return ret

# Spike does not support writing to some signaling addresses, but at the same time, we do not need it for spike resolution anyway. So let's replace it with an infinite loop.
def finalblock_spike_resolution():
    # Infinite loop in the end of the simulation
    return [JALInstruction("jal", 0, 0)]
