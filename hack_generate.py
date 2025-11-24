import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name('fuzzer')))
sys.path.insert(0, str(Path(__file__).with_name('makeelf')))

os.environ['CASCADE_ENV_SOURCED'] = ''
os.environ['CASCADE_DATADIR'] = 'cascade-data'
os.environ['CASCADE_PATH_TO_FIGURES'] = 'cascade-figures'
os.environ['CASCADE_RISCV_BITWIDTH'] = '64'
os.environ['CASCADE_DESIGN_PROCESSING_ROOT'] = str(Path(__file__, '../design-processing').resolve())

from cascade.fuzzerstate import FuzzerState as FuzzerStateBase
from cascade.basicblock import gen_basicblocks
class FuzzerState(FuzzerStateBase):
    randseed = 5000017
    nmax_bbs = 51
    nmax_instructions = None
    memsize = 881540  # 0xd7384

    # don't know what they are
    authorize_privileges = True
    nodependencybias = False

    design_base_addr = 0x80000000
    is_design_64bit = True

    design_name = 'boom'
    design_has_compressed_support = True
    design_has_fpu = True
    design_has_fpud = True
    design_has_muldiv = True
    design_has_amo = True
    design_has_misaligned_data_support = False
    design_has_supervisor_mode = True
    design_has_user_mode = True
    design_has_pmp = True

    def __init__(self, *a, **kw):
        assert (L := len(dir(self))) == 59

        random.seed(self.randseed)

        properties = [
            'fpuweight', 'isapickweights', 'exceptionoppickweights',
            'proba_change_rm', 'proba_ebreak_instead_of_ecall', 'proba_reg_starts_with_zero',
            'num_pickable_regs', 'num_pickable_floating_regs',
            ]
        assert all(not hasattr(self, p) for p in properties)
        self.gen_pick_weights()
        assert all(hasattr(self, p) for p in properties)
        assert (L := len(dir(self))) == 67, 'added 8 properties: %s' % L

        properties = [
            'initial_block_data_end',
            'initial_block_data_start',
            'random_block_content4by4bytes',

            'next_bb_addr',
            'memview',
            'memview_blacklist',

            'num_store_locations',
            'ctxsv_size_upperbound',

            'memstorestate',
            'intregpickstate',
            'floatregpickstate',
            'privilegestate',

            'instr_objs_seq',
            'bb_start_addr_seq',
            'saved_reg_states',

            'next_producer_id',

            'producer_id_to_tgtaddr',
            'producer_id_to_noreloc_spike',

            'initial_reg_data_addr',
            'initial_reg_data_content',

            'final_bb',
            'final_bb_base_addr',

            'ctxsv_bb',
            'ctxsv_bb_base_addr',
            'ctxsv_bb_jal_instr_id',
            'ctxdmp_bb',
            'ctxdmp_bb_base_addr',
            'ctxdmp_bb_jal_instr_id',

            'block_tail_instrs',

            'is_minstret_inaccurate_because_ecall_ebreak',

            'special_instrs_count',

            'fpuendis_coords',
            ]
        assert all(not hasattr(self, p) for p in properties)
        self.reset()
        assert all(hasattr(self, p) for p in properties)
        assert (L := len(dir(self))) == 99, 'added 32 properties: %s' % L

        properties = ['is_fpu_activated', 'proba_turn_on_off_fpu_again']
        assert all(not hasattr(self, p) for p in properties)
        assert self.design_has_fpu is True
        self.is_fpu_activated = True  # mutated
        self.proba_turn_on_off_fpu_again = random.random() * 0.1
        assert all(hasattr(self, p) for p in properties)
        assert (L := len(dir(self))) == 101, 'added 2 properties: %s' % L

print('\033[33m[INFO] fuzzerstate\033[m')
fuzzerstate = FuzzerState()
assert (L := len(dir(fuzzerstate))) == 101

print('\033[33m[INFO] gen_basicblocks\033[m')
gen_basicblocks(fuzzerstate)
assert (L := len(dir(fuzzerstate))) == 105, 'added 4 properties: %s' % L

print('\033[33m[INFO] spike_resolution\033[m')
from cascade.spikeresolution import spike_resolution
expected_intregvals, expected_floatregvals = spike_resolution(fuzzerstate, check_pc_spike_again=True)
assert (L := len(dir(fuzzerstate))) == 105, 'not added properties: %s' % L
assert len(expected_intregvals) >= fuzzerstate.num_pickable_regs-1
assert fuzzerstate.design_has_fpu is True
assert (L := len(expected_floatregvals)) == fuzzerstate.num_pickable_floating_regs

print('\033[33m[INFO] gen_elf_from_bbs\033[m')
from cascade.genelf import gen_elf_from_bbs
rtl_elfpath = gen_elf_from_bbs(
        fuzzerstate,
        is_spike_resolution=False,
        prefixname='rtl',
        test_identifier=fuzzerstate.instance_to_str(),
        start_addr=fuzzerstate.design_base_addr,
        )

print('\033[32m================\033[m')
