# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script provides a facility to profile designs in terms of:
# - Supported medeleg bits
# - WLRL behavior for writes to mcause (we assume that the behavior is the same for scause)

#   from params.runparams import DO_ASSERT
#   from rv.csrids import CSR_IDS
#   from rv.asmutil import li_into_reg
#   from common.designcfgs import get_design_boot_addr, is_design_32bit, get_design_stop_sig_addr, get_design_reg_dump_addr, design_has_supervisor_mode
#   from params.fuzzparams import RDEP_MASK_REGISTER_ID
#   from cascade.cfinstructionclasses import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, CSRImmInstruction, CSRRegInstruction, SpecialInstruction
#   from cascade.fuzzerstate import FuzzerState
#   from cascade.genelf import gen_elf_from_bbs
#   from cascade.fuzzsim import runtest_verilator_forprofiling

###
# Internal functions
###

# The snippet will dump a register value of the medeleg when fed with ones and then read back
# @param design_name: the name of the design to profile
# @return a snippet that dumps the register value
def __gen_medeleg_profiling_snippet(design_name: str):
    # Get some info about the design
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")
    #print(f'{hex(stopsig_addr)=} {hex(regdump_addr)=}')
    # hex(stopsig_addr)='0x60000000' hex(regdump_addr)='0x60000010'

    if DO_ASSERT:
        assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        assert stopsig_addr < 0x80000000, f"For the destination address `{hex(stopsig_addr)}`, we will need to manage sign extension, which is not yet implemented here."

    # We use the fuzzerstate for convenience but use very few of its features for this function's purposes. In particular, we do not bother about memviews.
    #print(f'{hex(get_design_boot_addr(design_name))=}')
    # hex(get_design_boot_addr(design_name))='0x80000000'
    fuzzerstate = FuzzerState(
            get_design_boot_addr(design_name),
            design_name,
            memsize=1 << 16,
            randseed=0,
            nmax_bbs=1,
            authorize_privileges=True)

    fuzzerstate.reset()
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    is_design_64bit = not is_design_32bit(design_name)

    ###
    # Write -1 into medeleg, then read it back
    ###

    # Write full ones into the medeleg register
    fuzzerstate.add_instruction(RegImmInstruction("addi", 1, 0, -1, is_design_64bit))
    fuzzerstate.add_instruction(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.MEDELEG))
    # Read medeleg into register 1.
    fuzzerstate.add_instruction(CSRImmInstruction("csrrwi", 1, 0, CSR_IDS.MEDELEG))

    # Dump the register
    lui_imm, addi_imm = li_into_reg(regdump_addr)
    fuzzerstate.add_instruction(ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm, is_design_64bit))
    fuzzerstate.add_instruction(RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_design_64bit))
    fuzzerstate.add_instruction(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1, is_design_64bit))
    fuzzerstate.add_instruction(SpecialInstruction("fence"))

    # Quit the simulation
    lui_imm, addi_imm = li_into_reg(stopsig_addr)
    fuzzerstate.add_instruction(ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm, is_design_64bit))
    fuzzerstate.add_instruction(RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_design_64bit))
    fuzzerstate.add_instruction(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1, is_design_64bit))
    fuzzerstate.add_instruction(SpecialInstruction("fence"))

    #print('\033[32m')
    #for i in fuzzerstate.instr_objs_seq[-1]:
    #    print(i.instr_str, '\t', i.gen_bytecode_int(False).to_bytes(4, 'little'))
    #print('\033[m')
    return fuzzerstate


def __get_medeleg_mask(design_name: str):
    # The fuzzerstate contains the snippet that dumps a register value of 1 if an exception occurred, else a value of 0
    fuzzerstate = __gen_medeleg_profiling_snippet(design_name)
    rtl_elfpath = gen_elf_from_bbs(
            fuzzerstate,
            is_spike_resolution=False,
            prefixname='medelegprofiling',
            test_identifier=design_name,
            start_addr=fuzzerstate.design_base_addr)
    return runtest_verilator_forprofiling(fuzzerstate, rtl_elfpath, 1)

###
# Exposed functions
###

PROFILED_MEDELEG_MASK = None

def profile_get_medeleg_mask(design_name: str):
    if "picorv32" in design_name:
        return 0 # This design does not support medeleg
    global PROFILED_MEDELEG_MASK
    PROFILED_MEDELEG_MASK = __get_medeleg_mask(design_name)
    print(f'\033[32m{hex(PROFILED_MEDELEG_MASK)=}\033[m')

# @return the mask of medeleg bits that are supported by the design
def get_medeleg_mask(design_name: str):
    if PROFILED_MEDELEG_MASK is None:
        raise Exception("Error: get_medeleg_mask was called before profiling.")
    return PROFILED_MEDELEG_MASK


####################


def get_medeleg_mask(design_name: str):
    assert design_name == 'boom'
    return 0xffff4f13020f1f13  # x01
