# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script is responsible for generating the basic blocks

from params.runparams import DO_ASSERT
from common.spike import SPIKE_STARTADDR
from rv.csrids import CSR_IDS
from params.fuzzparams import BRANCH_TAKEN_PROBA, LIMIT_MEM_SATURATION_RATIO, RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES
from cascade.randomize.createcfinstr import create_instr, create_regfsm_instrobjs
from cascade.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
from cascade.randomize.pickisainstrclass import gen_next_isainstrclass, ISAInstrClass
from cascade.randomize.pickmemop import pick_memop_addr, get_alignment_bits, is_instrstr_load
from cascade.randomize.pickfpuop import gen_fpufsm_instrs
from cascade.randomize.pickexceptionop import gen_exception_instr, gen_tvecfill_instr, gen_epcfill_instr, gen_medeleg_instr, gen_ppfill_instrs
from cascade.randomize.pickrandomcsrop import gen_random_csr_op
from cascade.randomize.pickprivilegedescentop import gen_priv_descent_instr
from cascade.cfinstructionclasses import is_placeholder, JALInstruction, JALRInstruction, BranchInstruction, ExceptionInstruction, TvecWriterInstruction, EPCWriterInstruction, GenericCSRWriterInstruction, MisalignedMemInstruction, PrivilegeDescentInstruction, EcallEbreakInstruction, SimpleExceptionEncapsulator, CSRRegInstruction
from cascade.util import get_range_bits_per_instrclass, IntRegIndivState, BASIC_BLOCK_MIN_SPACE, INSTRUCTIONS_BY_ISA_CLASS
from cascade.finalblock import get_finalblock_max_size,finalblock
from cascade.initialblock import gen_initial_basic_block
from cascade.blacklist import blacklist_changing_instructions, blacklist_final_block, blacklist_context_setter
from cascade.privilegestate import PrivilegeStateEnum

import random

# @brief Generates a series of basic blocks.
# Does not transmit the next bb address to the control flow instructions.
# @param fuzzerstate a freshly created fuzzerstate.
def gen_basicblocks(fuzzerstate):
    def freepairs():
        return [tuple(map(hex, v)) for v in fuzzerstate.memview.freepairs]

    print('\033[33m[INFO]\033[m reset')
    fuzzerstate.reset()
    assert not hasattr(fuzzerstate, 'curr_bb_start_addr')
    assert fuzzerstate.memview.freepairs == [(0x0, 0x10000)]
    assert len(fuzzerstate.instr_objs_seq) == 0
    assert fuzzerstate.num_store_locations == 23
    assert fuzzerstate.num_pickable_regs == 24
    assert fuzzerstate.num_pickable_floating_regs == 9
    assert fuzzerstate.initial_reg_data_content == []

    print('\033[33m[INFO]\033[m gen_initial_basic_block')
    gen_initial_basic_block(fuzzerstate, SPIKE_STARTADDR)
    assert fuzzerstate.curr_bb_start_addr == 0x0
    assert fuzzerstate.initial_reg_data_addr == 0x120
    assert fuzzerstate.initial_block_data_start == 0x120
    assert fuzzerstate.initial_block_data_end == 0x220
    assert fuzzerstate.memview.freepairs == [(0x224, 0x10000)]
    assert len(fuzzerstate.instr_objs_seq) == 1
    assert fuzzerstate.next_bb_addr == 0x7f30
    assert len(fuzzerstate.saved_reg_states) == 0
    assert len(fuzzerstate.initial_reg_data_content) == 32

    fuzzerstate.save_reg_state()
    assert len(fuzzerstate.saved_reg_states) == 1

    fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, BASIC_BLOCK_MIN_SPACE)
    assert fuzzerstate.memview.freepairs == [(0x224, 0x7f30), (0x7f48, 0x10000)]

    print('\033[33m[INFO]\033[m Generate the random data block')
    gen_random_data_block(fuzzerstate)
    assert fuzzerstate.random_data_block_start_addr == 0xd794
    assert fuzzerstate.random_data_block_end_addr == 0xd7b0
    assert fuzzerstate.memview.freepairs == [(0x224, 0x7f30), (0x7f48, 0xd794), (0xd7b0, 0x10000)]
    assert len(fuzzerstate.random_block_content4by4bytes) == 7

    print('\033[33m[INFO]\033[m allocate final basic block')
    alloc_final_basic_block(fuzzerstate)
    assert fuzzerstate.final_bb_base_addr == 0x2d7c
    assert fuzzerstate.memview.freepairs == [(0x224, 0x2d7c), (0x32ec, 0x7f30), (0x7f48, 0xd794), (0xd7b0, 0x10000)]

    # Reserve space for the context setter basic block, but do not instantiate
    # it because we do not know yet what it will look like until we have a concrete
    # context to restore. Until then, we just know arbitrary bounds.
    result = alloc_context_saver_bb(fuzzerstate)
    assert result is True
    assert fuzzerstate.ctxsv_size_upperbound == 0xedc  # XXX: comes from `cascade.contextreplay.get_context_setter_max_size`
    assert fuzzerstate.ctxsv_bb_base_addr == 0x5674
    assert fuzzerstate.memview.freepairs == [(0x224, 0x2d7c), (0x32ec, 0x5674), (0x6550, 0x7f30), (0x7f48, 0xd794), (0xd7b0, 0x10000)]

    # XXX: unknown usage
    # Finally, generate the store locations. This can be swapped with generating the final basic block.
    assert len(fuzzerstate.memview.freepairs) == 5
    assert len(fuzzerstate.memstorestate.store_locations) == 0
    fuzzerstate.memstorestate.init_store_locations(fuzzerstate.num_store_locations, fuzzerstate.memview)
    assert len(fuzzerstate.memview.freepairs) == 28
    assert len(fuzzerstate.memstorestate.store_locations) == 23  # XXX: used on load/store?
    assert fuzzerstate.curr_bb_start_addr == 0x0
    assert fuzzerstate.get_num_fuzzing_instructions_sofar() == 0, "We should have generated only one basic block so far."
    assert fuzzerstate.has_reached_max_instr_num() == False, "We should not have reached the max number of instructions yet."
    assert fuzzerstate.nmax_instructions is None
    assert len(fuzzerstate.instr_objs_seq) == 1
    assert fuzzerstate.next_bb_addr == 0x7f30

    ########################################

    assert len(fuzzerstate.memview.freepairs) == 27 + 1  # has allocated for the next basic block
    assert len(fuzzerstate.instr_objs_seq) == 1
    assert fuzzerstate.is_fpu_activated is True, f'{fuzzerstate.is_fpu_activated=}'
    while True:
        if not (success := gen_basicblock(fuzzerstate)):
            break

        # Save the register states
        fuzzerstate.save_reg_state()

        # Stop generating if no more bb can be produced
        assert not (fuzzerstate.memview.get_allocated_ratio() >= LIMIT_MEM_SATURATION_RATIO)
        assert not fuzzerstate.has_reached_max_instr_num()
        if fuzzerstate.nmax_bbs is not None and len(fuzzerstate.instr_objs_seq) >= fuzzerstate.nmax_bbs:
            assert len(fuzzerstate.memview.freepairs) == 28 + max(0, fuzzerstate.nmax_bbs - 2), len(fuzzerstate.memview.freepairs)
            assert len(fuzzerstate.instr_objs_seq) in (2, fuzzerstate.nmax_bbs)
            break

        fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, BASIC_BLOCK_MIN_SPACE)

    #assert fuzzerstate.is_fpu_activated is False, f'{fuzzerstate.is_fpu_activated=}'

    ########################################

    # XXX: it pops out unsuitable basic blocks, while the jump range is limited by the immediate of `jal` and `jalr` 
    # Find a suitable last bb and connect it with the final block
    success = pop_last_bbs_to_connect_with_final_block(fuzzerstate)
    assert success is True
    #assert len(fuzzerstate.instr_objs_seq) in (2, 1, fuzzerstate.nmax_bbs, fuzzerstate.nmax_bbs-1)

    # Generate the content of the final basic block, now that we know the final privilege level.
    print('\033[33m[INFO]\033[m generate final basic block')
    assert fuzzerstate.final_bb == []
    fuzzerstate.final_bb = finalblock(fuzzerstate, fuzzerstate.design_name)
    #assert len(fuzzerstate.final_bb) in (85, 56)


    print(f'\033[33m[INFO]\033[m generate blacklist')
    # XXX: update `memview_blacklist`, effect the value of placeholder
    # Forbid loads from addresses where instructions change between spike resolution and RTL sim.
    blacklist_changing_instructions(fuzzerstate)
    # Must be done once the bb is created, else we could also blacklist upper 
    # bounds over the basic block size.
    blacklist_final_block(fuzzerstate) 
    blacklist_context_setter(fuzzerstate)

    # Generate addresses for memory operations
    memop_addrs = gen_memop_addrs(fuzzerstate)
    #print(f'{[hex(a) for a in memop_addrs]=}')
    fuzzerstate.producer_id_to_tgtaddr, fuzzerstate.producer_id_to_noreloc_spike = gen_producer_id_to_tgtaddr(fuzzerstate, memop_addrs)
    #print(f'{len(fuzzerstate.producer_id_to_tgtaddr)=}')
    #print(f'{len(fuzzerstate.producer_id_to_noreloc_spike)=}')  # XXX: unused

    # Debug only
    # for bb_id, bb in enumerate(fuzzerstate.instr_objs_seq):
    #     for bb_instr_id, bb_instr in enumerate(bb):
    #         curr_addr = fuzzerstate.bb_start_addr_seq[bb_id] + bb_instr_id * 4 # NO_COMPRESSED
    #         if curr_addr == 0x4e198:
    #             print('BB id:', bb_instr_id)
    #             print('Instr type:', bb_instr)
    #             print('Plan taken:', bb_instr.plan_taken)
    # print('Start addr:', hex(fuzzerstate.bb_start_addr_seq[147]))


def gen_basicblock(fuzzerstate) -> bool:
    """
    The first BASIC_BLOCK_MIN_SPACE must be pre-allocated. The rationale is that we
    want to pre-allocate at least for the first basic block, to prevent the store
    data from landing exactly there.
    @return True iff the creation is successful
    """
    #fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block
    fuzzerstate.instr_objs_seq.append([])
    fuzzerstate.bb_start_addr_seq.append(fuzzerstate.next_bb_addr)
    fuzzerstate.curr_bb_start_addr, fuzzerstate.next_bb_addr = fuzzerstate.next_bb_addr, None

    def get_available_contig_space(freepairs, addr) -> "size":
        for curr_pair in freepairs:
            if addr in range(*curr_pair):
                return curr_pair[1] - addr
        else:
            return 0

    # XXX: maybe additional 0x18 + 4 is for expanding instructions
    # This points to the first address after the current basic block allocation.
    # The block allocation takes 16 bytes in advance, to avoid storing and then
    # not being able to continue expanding the basic block.
    assert BASIC_BLOCK_MIN_SPACE == 0x18
    curr_alloc_cursor = fuzzerstate.curr_bb_start_addr + BASIC_BLOCK_MIN_SPACE
    curr_isa_class = None # This is used in case there is only space for control flow
    fuzzerstate.curr_branch_taken = None  # XXX: used by `cascade.randomize.createcfinstr._create_BranchInstruction`
    while True:
        # We stop the instruction generation either when there is no more space
        # available, or when we encounter an end-of-state instruction
        contiguous_length = get_available_contig_space(fuzzerstate.memview.freepairs, curr_alloc_cursor)
        #print(f'{hex(curr_alloc_cursor)=}')
        if not (contiguous_length > BASIC_BLOCK_MIN_SPACE + 4):
            #print(f'{fuzzerstate.instr_objs_seq[-1]=}')
            #print(f'{len(fuzzerstate.instr_objs_seq[-1])=}')
            #print('\033[35m[DEBUG]\033[m inenough contiguous space')
            break

        is_block_terminated = False
        new_instrobjs = None
        #curr_addr = fuzzerstate.get_current_addr()
        curr_addr = fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4
        assert curr_alloc_cursor - curr_addr == 0x18

        # Get the next instruction class
        assert fuzzerstate.has_reached_max_instr_num() is False
        curr_isa_class = gen_next_isainstrclass(fuzzerstate)
        #if fuzzerstate.has_reached_max_instr_num():
        #    curr_isa_class = ISAInstrClass.JAL
        #else:
        #    curr_isa_class = gen_next_isainstrclass(fuzzerstate)

        # Generate instruction
        match curr_isa_class:

            # If this was a JAL due to reaching the max authorized number of instructions
            #case  ISAInstrClass.JAL if fuzzerstate.has_reached_max_instr_num():
            #    instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)
            #    assert instr_str == 'jal', f"Unexpected instruction string `{instr_str}`"
            #    new_instrobjs = [create_instr("jal", fuzzerstate, curr_addr)]
            #    ...

            # Generate next bb addr if the instruction will terminate the block
            # =================================================================

            # Privilege descent instruction or an mpp/spp write instruction
            case ISAInstrClass.DESCEND_PRV:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, 4)
                is_block_terminated = gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)
                assert is_block_terminated is True
                new_instrobjs = [gen_priv_descent_instr(fuzzerstate)]

            # Generate exception instruction
            case ISAInstrClass.EXCEPTION:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, 4)
                is_block_terminated = gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)
                assert is_block_terminated is True
                new_instrobjs = [gen_exception_instr(fuzzerstate)]

            # Create JAL/JALR instrction and generate next bb address
            case ISAInstrClass.JAL | ISAInstrClass.JALR:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, 4)
                is_block_terminated = gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)
                assert is_block_terminated is True
                instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)
                new_instrobjs = [create_instr(instr_str, fuzzerstate, curr_addr)]

            # Create taken branch instruction, non taken branch use default
            case ISAInstrClass.BRANCH:
                fuzzerstate.curr_branch_taken = random.random() < BRANCH_TAKEN_PROBA
                if fuzzerstate.curr_branch_taken:
                    fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, 4)
                    is_block_terminated = gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)
                    assert is_block_terminated is True

                instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)
                new_instrobjs = [create_instr(instr_str, fuzzerstate, curr_addr)]

            # XXX: others
            # ===========

            # Generate xPP register
            case ISAInstrClass.PPFSM:
                new_instrobjs = gen_ppfill_instrs(fuzzerstate)

            # Register offset value generation
            case ISAInstrClass.REGFSM:
                new_instrobjs = create_regfsm_instrobjs(fuzzerstate)

            # FPU enable-disable instruction, location is kept for the reduce
            case ISAInstrClass.FPUFSM:
                new_instrobjs = gen_fpufsm_instrs(fuzzerstate)

            # Populates TVEC
            case ISAInstrClass.TVECFSM:
                new_instrobjs = [gen_tvecfill_instr(fuzzerstate)]

            # Populates EPC
            case ISAInstrClass.EPCFSM:
                new_instrobjs = [gen_epcfill_instr(fuzzerstate)]

            # Generate random CSR
            case ISAInstrClass.RANDOM_CSR:
                new_instrobjs = [gen_random_csr_op(fuzzerstate)]

            # Generate MEDELEG value
            case ISAInstrClass.MEDELEG:
                assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE, "medeleg can only be used in machine mode, and we do not an exception here."
                new_instrobjs = [gen_medeleg_instr(fuzzerstate)]

            # Generate instruction which does not depend on the CPU state
            case _:
                instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)
                new_instrobjs = [create_instr(instr_str, fuzzerstate, curr_addr)]

        # Update the program view
        fuzzerstate.instr_objs_seq[-1].extend(new_instrobjs)

        # Return if the block is over
        if is_block_terminated:
            #print(f'{fuzzerstate.instr_objs_seq[-1]=}')
            #print(f'{len(fuzzerstate.instr_objs_seq[-1])=}')
            #print('\033[35m[DEBUG]\033[m is_block_terminated')
            return True

        # Update memory and generate next instruction
        instr_mem_size = len(new_instrobjs) * 4
        assert instr_mem_size < BASIC_BLOCK_MIN_SPACE
        fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, instr_mem_size)
        curr_alloc_cursor += instr_mem_size

    # This is reached if we need to urgently jump to the next basic block.
    # The algorithm is the following: if there is a possibility to jump immediately, 
    # then do so. Else, prepare the registers as fast as possible.
    curr_isa_class = random.choices([ISAInstrClass.JAL, ISAInstrClass.JALR, ISAInstrClass.BRANCH], [1, 1, 1], k=1)[0]

    # No need for any preparation if jal, because it has no true dependency
    if curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.BRANCH):
        curr_addr = fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4

        # Gen the next bb addr
        if not (success := gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)):
            return False

        if curr_isa_class == ISAInstrClass.JAL:
            fuzzerstate.instr_objs_seq[-1].append(create_instr("jal", fuzzerstate, curr_addr))

        else:
            assert curr_isa_class == ISAInstrClass.BRANCH
            fuzzerstate.curr_branch_taken = True
            # The branch type does not batter because it will be re-determined once the operand values are known
            fuzzerstate.instr_objs_seq[-1].append(create_instr("bne", fuzzerstate, curr_addr))
    else:
        # For JALR, bring some reg to maturity, and then insert the control flow instruction
        assert curr_isa_class == ISAInstrClass.JALR

        # XXX: it appends a few instructions
        fuzzerstate.intregpickstate.bring_some_reg_to_state(IntRegIndivState.CONSUMED, fuzzerstate)

        curr_addr = fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4

        # Gen the next bb addr
        if not (success := gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)):
            return False

        fuzzerstate.add_instruction(create_instr('jalr', fuzzerstate, curr_addr))

    return True

# @brief This function generates the producer_id_to_tgtaddr dictionary and the 
# producer_id_to_noreloc_spike dictionaries.
def gen_producer_id_to_tgtaddr(fuzzerstate, memop_addrs):
    # Two steps. First, generate producer_id_to_tgtaddr. Then, use it to populate 
    # the producers with target addresses. The second step is done in another function.

    # Step 1
    index_in_memaddr_array = 0
    # This variable lets us know to which address we wish to jump when some CF
    # s instruction is taken
    index_in_bb_start_addr_seq = 1 
    # producer_id_to_tgtaddr[producer_id] = tgt_addr
    producer_id_to_tgtaddr = dict() 
    # producer_id_to_noreloc_spike[producer_id] = bool, where bool is true if the 
    # value we want to specify should not be relocated for spike
    producer_id_to_noreloc_spike = dict() 

    # To facilitate backward propagation of addresses during exceptions, we recall the tvec writes.
    # When they are consumed, we forget them.
    last_mtvec = None # last_mtvec is a tuple (bb_id, instr_id)
    last_stvec = None # last_stvec is a tuple (bb_id, instr_id)
    last_mepc = None  # last_mepc  is a tuple (bb_id, instr_id)
    last_sepc = None  # last_sepc  is a tuple (bb_id, instr_id)

    for bb_id, bb_instrlist in enumerate(fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrlist):

            ###
            # First check for instructions that do not have an instruction string, such as
            #  placeholder instructions or some CSR write instructions.
            ###

            if is_placeholder(bb_instr):
                continue

            # To facilitate backward propagation of addresses during exceptions
            elif isinstance(bb_instr, TvecWriterInstruction):
                if bb_instr.is_mtvec:
                    last_mtvec = (bb_id, bb_instr_id)
                else:
                    last_stvec = (bb_id, bb_instr_id)

            # To facilitate backward propagation of addresses during trap returns
            elif isinstance(bb_instr, EPCWriterInstruction):
                if bb_instr.is_mepc:
                    last_mepc = (bb_id, bb_instr_id)
                else:
                    last_sepc = (bb_id, bb_instr_id)

            # To facilitate backward propagation of addresses during exceptions
            elif isinstance(bb_instr, GenericCSRWriterInstruction):
                # For producer_id_to_noreloc_spike
                if bb_instr.csr_instr.csr_id == CSR_IDS.MEDELEG:
                    producer_id_to_noreloc_spike[bb_instr.producer_id] = True
                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = bb_instr.val_to_write_cpu

            # In case of a privilege descent instruction
            elif isinstance(bb_instr, PrivilegeDescentInstruction):
                # Extremely similar to handling exception instruction below
                # Check that a corresponding xepc has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mret and last_mepc) or (not bb_instr.is_mret and last_sepc), "No epc found for privilege descent instruction. Values are: last_mepc = {}, last_sepc = {}, bb_instr.is_mret = {}".format(last_mepc, last_sepc, bb_instr.is_mret)

                # Get the epc instr's producer id
                if bb_instr.is_mret:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_mepc[0]][last_mepc[1]].producer_id
                else:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_sepc[0]][last_sepc[1]].producer_id

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert epc_producer_id > 0

                if DO_ASSERT:
                    assert epc_producer_id == -1 or not epc_producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[epc_producer_id] = addr
                # Do not use twice the same epc value because we want to jump to 
                # a new basic block.
                if bb_instr.is_mret:
                    last_mepc = None
                else:
                    last_sepc = None

            # In case of an exception instruction, find the last corresponding 
            # tvec and transmit the target address
            elif isinstance(bb_instr, ExceptionInstruction):
                # Check that a corresponding tvec has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mtvec and last_mtvec) or (not bb_instr.is_mtvec and last_stvec), "No tvec found for exception instruction. Values are: last_mtvec = {}, last_stvec = {}, bb_instr.is_mtvec = {}".format(last_mtvec, last_stvec, bb_instr.is_mtvec)

                # Get the tvec instr's producer id
                if bb_instr.is_mtvec:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_mtvec[0]][last_mtvec[1]].producer_id
                else:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_stvec[0]][last_stvec[1]].producer_id

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert tvec_producer_id > 0

                if DO_ASSERT:
                    assert tvec_producer_id == -1 or not tvec_producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[tvec_producer_id] = addr

                # Do not use twice the same tvec value because we want to jump to a new basic block.
                if bb_instr.is_mtvec:
                    last_mtvec = None
                else:
                    last_stvec = None

                # Some exceptions also require their own produced register, not only 
                # for tvec but also to make a targeted memory operation
                if bb_instr.producer_id is not None:
                    del addr
                    if isinstance(bb_instr, MisalignedMemInstruction):
                        addr = bb_instr.misaligned_addr
                    else:
                        raise Exception("We expected only MisalignedMemInstruction to have a producer_id.")

                    if DO_ASSERT:
                        assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                    producer_id_to_tgtaddr[bb_instr.producer_id] = addr

            ###
            # Else, check for "traditional" instructions, which have an instruction string.
            ###

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.JALR]:
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert bb_instr.producer_id > 0
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = addr

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM] or \
                bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM64] or \
                bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPU] or \
                bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPUD]:
                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = memop_addrs[index_in_memaddr_array]
                index_in_memaddr_array += 1

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.JAL] or \
                (bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.BRANCH] and bb_instr.plan_taken):
                # If this is the last before the final block, we need to steer toward the final block.
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    curr_addr = fuzzerstate.bb_start_addr_seq[bb_id] + bb_instr_id * 4 # NO_COMPRESSED
                    bb_instr.imm = fuzzerstate.final_bb_base_addr - curr_addr
                index_in_bb_start_addr_seq += 1

    if DO_ASSERT:
        index_in_memaddr_array = len(memop_addrs)

    return producer_id_to_tgtaddr, producer_id_to_noreloc_spike

def gen_next_bb_addr(fuzzerstate, isa_class: ISAInstrClass, curr_addr: int):
#def gen_next_bb_addr(fuzzerstate, isa_class: ISAInstrClass, curr_addr: int, curr_alloc_cursor: int, alloc_mem: bool = True):
    """
    Given the provided control flow instruction, finds a location for a new block, 
    but does not allocate it.
    @return False if could not find a next bb address
    """
    # Allocate current instruction if called by the main loop, else we used the 
    # reserved memory
    #if alloc_mem:
    #    fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, 4)

    # We must select the next basic block address before the resolution
    instr_range = get_range_bits_per_instrclass(isa_class)
    left_boundary = curr_addr - (1 << instr_range)
    right_boundary = curr_addr + (1 << instr_range)

    assert fuzzerstate.next_bb_addr is None
    fuzzerstate.next_bb_addr = fuzzerstate.memview.gen_random_free_addr(4, BASIC_BLOCK_MIN_SPACE, left_boundary, right_boundary)
    #print(f'{isa_class=} {hex(fuzzerstate.next_bb_addr)=}')

    # If we could not find a new address where to place the next basic block,
    # then return and consider this stage complete.
    if fuzzerstate.next_bb_addr is None:
        # XXX: for `nmax_bbs` is None
        # Abort the bb
        fuzzerstate.restore_previous_state()  # XXX: remove the last basic block and related
        return False
    else:
        return True

# This must be done early, say, just after generating the first basic block, to ensure that we have enough space.
def gen_random_data_block(fuzzerstate):
    #lenbytes = random.randrange(RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES)
    lenbytes = random.randrange(12, 64)
    fuzzerstate.random_data_block_start_addr = fuzzerstate.memview.gen_random_free_addr(
        alignment_bits=2,
        min_space=lenbytes,
        left_bound=0,
        right_bound=fuzzerstate.memsize)
    fuzzerstate.random_data_block_end_addr = fuzzerstate.random_data_block_start_addr + lenbytes
    print(f'{fuzzerstate.random_data_block_start_addr=}')
    print(f'{fuzzerstate.random_data_block_end_addr=}')
    if DO_ASSERT:
        assert fuzzerstate.random_data_block_start_addr is not None, f"Maybe you should create the random data block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.random_data_block_start_addr, lenbytes)
    # Generate the random data
    for _ in range(fuzzerstate.random_data_block_start_addr, fuzzerstate.random_data_block_end_addr, 4):
        fuzzerstate.random_block_content4by4bytes.append(random.randrange(0, 2**32))

# This must be done early, say, just after generating the first basic block, to 
# ensure that we have enough space.
def alloc_final_basic_block(fuzzerstate):
    lenbytes = get_finalblock_max_size() * 4 # NO_COMPRESSED
    fuzzerstate.final_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, 0, fuzzerstate.memsize)
    if DO_ASSERT:
        assert fuzzerstate.final_bb_base_addr is not None, f"Maybe you should create the final basic block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.final_bb_base_addr, lenbytes)

# This must be done early, say, just after generating the final basic block, to 
# ensure that we have enough space.
def alloc_context_saver_bb(fuzzerstate):
    # For the contextsaver, we first want to know the base address before we generate
    #  the basic block because we do loads and stores, which require absolute addresses.
    fuzzerstate.ctxsv_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, fuzzerstate.ctxsv_size_upperbound, 0, fuzzerstate.memsize)
    if fuzzerstate.ctxsv_bb_base_addr is None:
        return False
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.ctxsv_bb_base_addr, fuzzerstate.ctxsv_size_upperbound)
    return True

# This function is a bit tricky. The objective is to remove the final basic 
# blocks until we find a basic block that can reach the final block. For example, 
# a far JAL may not be able to each the final block. This should be done once all 
# the basic blocks have been inserted until a stop condition was met, such as no 
# more space found for another bb, or memory usage above a certain percentage.
# @return True iff the insertion succeeded. If False, the whole test case 
# generation is considered failed.
def pop_last_bbs_to_connect_with_final_block(fuzzerstate):
    popped_at_least_once = False
    while fuzzerstate.instr_objs_seq:
        # Check whether the last element can target the final bb
        last_cf_instr_base_addr = fuzzerstate.bb_start_addr_seq[-1] + (len(fuzzerstate.instr_objs_seq[-1])-1) * 4 # NO_COMPRESSED
        last_instr = fuzzerstate.instr_objs_seq[-1][-1]
        #print(f'{hex(last_cf_instr_base_addr)=} {last_instr=}')

        if isinstance(last_instr, JALInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.JAL)
        elif isinstance(last_instr, JALRInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.JALR)
        elif isinstance(last_instr, BranchInstruction) and last_instr.plan_taken:
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.BRANCH)
        elif isinstance(last_instr, PrivilegeDescentInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.DESCEND_PRV)
        elif isinstance(last_instr, ExceptionInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.EXCEPTION)
        else:
            raise ValueError(f"Unexpectedly got instruction `{last_instr}`")
        #print(f'{range_bits=}')

        if fuzzerstate.final_bb_base_addr >= last_cf_instr_base_addr - (1 << range_bits) \
                and fuzzerstate.final_bb_base_addr < last_cf_instr_base_addr + (1 << range_bits):
            # The last basic block of the series is a candidate for jumping to the final block.
            # The target address of the last cf instruction will be injected later.
            if popped_at_least_once:
                fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            return True

        # else, in case the last block could not reach the final block, then we discard it and try with the previous one.
        popped_at_least_once = True
        fuzzerstate.instr_objs_seq.pop()
        fuzzerstate.bb_start_addr_seq.pop()
        fuzzerstate.saved_reg_states.pop()
    return False

# @return a list of addresses for the memory operations, in their order of occurrence
def gen_memop_addrs(fuzzerstate):
    ret = []
    for bb_instrlist in fuzzerstate.instr_objs_seq:
        for bb_instr in bb_instrlist:
            if is_placeholder(bb_instr):
                continue
            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM] or \
            bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM64] or \
            bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPU] or \
            bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPUD]:
                memop_addr = pick_memop_addr(fuzzerstate, is_instrstr_load(bb_instr.instr_str), get_alignment_bits(bb_instr.instr_str))
                ret.append(memop_addr)
    return ret


########################################


def gen_random_data_block(fuzzerstate):
    """
    -> fuzzerstate.memview.freepairs
    -> fuzzerstate.random_block_content4by4bytes
    -> fuzzerstate.random_data_block_start_addr
    -> fuzzerstate.random_data_block_end_addr
    """
    #lenbytes = random.randrange(RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES)
    lenbytes = random.randrange(12, 64)
    start_address = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, 0, fuzzerstate.memsize)
    assert start_address is not None, "Maybe you should create the random data block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(start_address, lenbytes)  # update `fuzzerstate.memview.freepairs`

    # XXX: without the random data, somehow `instr_objs_seq` increases by 1
    # XXX: unknown the usage while the address and number are independent from the number of basic blocks generated

    # Generate the random data
    assert start_address == 0xd794
    assert start_address + lenbytes == 0xd7b0
    assert lenbytes == 28
    assert lenbytes // 4 == 7
    fuzzerstate.random_block_content4by4bytes.extend(
            random.randrange(0, 2**32)  # 4 bytes 32-bits
            for _ in range(lenbytes // 4))

    fuzzerstate.random_data_block_start_addr = start_address
    fuzzerstate.random_data_block_end_addr = start_address + lenbytes
    #print(f'{hex(fuzzerstate.random_data_block_start_addr)=}')
    #print(f'{hex(fuzzerstate.random_data_block_end_addr)=}')


def alloc_final_basic_block(fuzzerstate):
    """
    -> fuzzerstate.memview.freepairs
    -> fuzzerstate.final_bb_base_addr
    """
    from params.fuzzparams import MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS

    assert MAX_NUM_PICKABLE_REGS == 25
    assert MAX_NUM_PICKABLE_FLOATING_REGS == 14

    # XXX: additional 3 + 1 + 5 = 9 instructions
    #      moreover, it seems accidentally multiplied by 4
    # XXX: 14 rather than 10 ...
    finalblock_size = (10 + 2 * MAX_NUM_PICKABLE_REGS + 2 * MAX_NUM_PICKABLE_FLOATING_REGS - 1) * 4  # XXX: strange formula
    lenbytes = finalblock_size * 4
    #print(f'finalblock_size={hex(finalblock_size)} lenbytes={hex(lenbytes)}')
    start_address = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, 0, fuzzerstate.memsize)
    assert start_address is not None, f"Maybe you should create the final basic block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(start_address, lenbytes)

    fuzzerstate.final_bb_base_addr = start_address
    #print(f'{hex(fuzzerstate.final_bb_base_addr)=}')


from cascade import cfinstructionclasses as cf
placeholder = (
        cf.PlaceholderProducerInstr0,
        cf.PlaceholderProducerInstr1,
        cf.PlaceholderPreConsumerInstr,
        cf.PlaceholderConsumerInstr,
        )
load_store = sum((
        INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM],
        INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM64],
        INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPU],
        INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPUD],
        ), [])

def gen_memop_addrs(fuzzerstate):
    ret = []
    for instruction in (bb_instr for bb_instrlist in fuzzerstate.instr_objs_seq for bb_instr in bb_instrlist):
        # XXX: filter placeholder out because it does not have `.instr_str`
        if not isinstance(instruction, placeholder) and instruction.instr_str in load_store:
            # XXX: if `load`, take `store` address or generate a free address;
            #      otherwise, take `store` address
            memop_addr = pick_memop_addr(
                    fuzzerstate,
                    is_curr_load=is_instrstr_load(instruction.instr_str),
                    alignment_bits=get_alignment_bits(instruction.instr_str),
                    )
            ret.append(memop_addr)
    #assert ret == [0xe30, 0xb3e0, 0x24f0, 0xb3e0, 0xb3e0, 0x7970, 0xb3e0, 0xb3e0, 0x2168, 0xb3e0, 0xb3e0, 0xd328, 0xb4d0, 0xb3e0, 0xe248, 0x7b68, 0x8410, 0xf660, 0x69b8, 0xb3e0, 0xcd38, 0xb460, 0xc7f8, 0xb3e0, 0xb3e0, 0xa718, 0xb600, 0xb3e0, 0x9b78, 0xb3e0, 0xb3e0, 0xb3e0, 0xb3e4, 0xb3e4, 0xcf40, 0xa938, 0x2904, 0x1220, 0x9ea8, 0x6f2e, 0x278, 0x546a, 0xb3e6, 0xe500, 0xb3e4, 0xb3e0, 0xb3e4, 0x934d, 0xb3e6, 0xb3e0, 0xb3e0, 0x16ee, 0xb3e4, 0xef14, 0xf519, 0xb3e5, 0xb3e0, 0xb3e4, 0x92fc, 0xb3e4, 0xb3e0, 0xfcb0, 0xb3e4, 0xb3e0, 0xb3e0, 0xb3e4]
    return ret


def gen_producer_id_to_tgtaddr(fuzzerstate, memop_addrs) -> tuple[dict[producer_id, tgt_addr], dict[producer_id, bool]]:
    """
    return :dict:`producer_id_to_tgtaddr` and :dict:`producer_id_to_noreloc_spike`
    """
    # Two steps. First, generate producer_id_to_tgtaddr. Then, use it to populate 
    # the producers with target addresses. The second step is done in another function.

    # Step 1
    index_in_memaddr_array = 0
    # This variable lets us know to which address we wish to jump when some CF
    # s instruction is taken
    index_in_bb_start_addr_seq = 1 
    # producer_id_to_tgtaddr[producer_id] = tgt_addr
    producer_id_to_tgtaddr = dict() 
    # producer_id_to_noreloc_spike[producer_id] = bool, where bool is true if the 
    # value we want to specify should not be relocated for spike
    producer_id_to_noreloc_spike = dict() 

    # To facilitate backward propagation of addresses during exceptions, we recall the tvec writes.
    # When they are consumed, we forget them.
    last_mtvec = None # last_mtvec is a tuple (bb_id, instr_id)
    last_stvec = None # last_stvec is a tuple (bb_id, instr_id)
    last_mepc = None  # last_mepc  is a tuple (bb_id, instr_id)
    last_sepc = None  # last_sepc  is a tuple (bb_id, instr_id)

    for bb_id, bb_instrlist in enumerate(fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrlist):

            ###
            # First check for instructions that do not have an instruction string, such as
            #  placeholder instructions or some CSR write instructions.
            ###

            if isinstance(bb_instr, placeholder):
                pass

            # To facilitate backward propagation of addresses during exceptions
            elif isinstance(bb_instr, TvecWriterInstruction):
                if bb_instr.is_mtvec:
                    last_mtvec = (bb_id, bb_instr_id)
                else:
                    last_stvec = (bb_id, bb_instr_id)

            # To facilitate backward propagation of addresses during trap returns
            elif isinstance(bb_instr, EPCWriterInstruction):
                if bb_instr.is_mepc:
                    last_mepc = (bb_id, bb_instr_id)
                else:
                    last_sepc = (bb_id, bb_instr_id)

            # To facilitate backward propagation of addresses during exceptions
            elif isinstance(bb_instr, GenericCSRWriterInstruction):
                # For producer_id_to_noreloc_spike
                if bb_instr.csr_instr.csr_id == CSR_IDS.MEDELEG:
                    producer_id_to_noreloc_spike[bb_instr.producer_id] = True

                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = bb_instr.val_to_write_cpu

            # In case of a privilege descent instruction
            elif isinstance(bb_instr, PrivilegeDescentInstruction):
                pass
                # XXX: won't enter this branch

                # Extremely similar to handling exception instruction below
                # Check that a corresponding xepc has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mret and last_mepc) or (not bb_instr.is_mret and last_sepc), "No epc found for privilege descent instruction. Values are: last_mepc = {}, last_sepc = {}, bb_instr.is_mret = {}".format(last_mepc, last_sepc, bb_instr.is_mret)

                # Get the epc instr's producer id
                if bb_instr.is_mret:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_mepc[0]][last_mepc[1]].producer_id
                else:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_sepc[0]][last_sepc[1]].producer_id

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert epc_producer_id > 0

                if DO_ASSERT:
                    assert epc_producer_id == -1 or not epc_producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[epc_producer_id] = addr
                # Do not use twice the same epc value because we want to jump to 
                # a new basic block.
                if bb_instr.is_mret:
                    last_mepc = None
                else:
                    last_sepc = None

            # In case of an exception instruction, find the last corresponding 
            # tvec and transmit the target address
            elif isinstance(bb_instr, ExceptionInstruction):
                # Check that a corresponding tvec has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mtvec and last_mtvec) or (not bb_instr.is_mtvec and last_stvec), "No tvec found for exception instruction. Values are: last_mtvec = {}, last_stvec = {}, bb_instr.is_mtvec = {}".format(last_mtvec, last_stvec, bb_instr.is_mtvec)

                # Get the tvec instr's producer id
                if bb_instr.is_mtvec:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_mtvec[0]][last_mtvec[1]].producer_id
                else:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_stvec[0]][last_stvec[1]].producer_id

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    # XXX: this branch is never taken
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert tvec_producer_id > 0

                if DO_ASSERT:
                    assert tvec_producer_id == -1 or not tvec_producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[tvec_producer_id] = addr

                # Do not use twice the same tvec value because we want to jump to a new basic block.
                if bb_instr.is_mtvec:
                    last_mtvec = None
                else:
                    last_stvec = None

                # Some exceptions also require their own produced register, not only 
                # for tvec but also to make a targeted memory operation
                if bb_instr.producer_id is None:
                    #print(f'{bb_instr=}')
                    pass
                else:
                    if not isinstance(bb_instr, MisalignedMemInstruction):
                        raise Exception("We expected only MisalignedMemInstruction to have a producer_id.")

                    producer_id_to_tgtaddr[bb_instr.producer_id] = addr = bb_instr.misaligned_addr

            ###
            # Else, check for "traditional" instructions, which have an instruction string.
            ###

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.JALR]:
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1

                if DO_ASSERT:
                    assert bb_instr.producer_id > 0
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)

                producer_id_to_tgtaddr[bb_instr.producer_id] = addr

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.JAL] or \
                (bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.BRANCH] and bb_instr.plan_taken):
                # If this is the last before the final block, we need to steer toward the final block.
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    curr_addr = fuzzerstate.bb_start_addr_seq[bb_id] + bb_instr_id * 4 # NO_COMPRESSED
                    bb_instr.imm = fuzzerstate.final_bb_base_addr - curr_addr
                index_in_bb_start_addr_seq += 1

            elif bb_instr.instr_str in load_store:
                # XXX: in initial block, `.producer_id` of fld/ld are `-1`
                #print(f'{bb_instr.instr_str=} {bb_instr.producer_id=} {hex(memop_addrs[index_in_memaddr_array])=}')
                producer_id_to_tgtaddr[bb_instr.producer_id] = memop_addrs[index_in_memaddr_array]
                index_in_memaddr_array += 1

            else:
                pass

    assert index_in_memaddr_array == len(memop_addrs)
    return producer_id_to_tgtaddr, producer_id_to_noreloc_spike
