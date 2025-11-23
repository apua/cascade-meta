# Reference: ``cd /cascade-meta/fuzzer && python3 -u do_fuzzsingle.py``

# Python dependnecies::
#
#   pip install -U pip
#   pip install numpy filelock
#   pip install git+https://github.com/flaviens/makeelf@finercontrol

# Run::
#
#   python hacking.py

# ``design-processing/design_repos.json`` defines the location of hardware design
# which is out of this repository and must be adjusted.

# The hardware design "BOOM" has config at following::
#
#   ./cascade-designs/cascade-chipyard/cascade-boom/meta/cfg.json

# The output of Verilator is required but not sure the usage::
#
#   ./verilator.out

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name('fuzzer')))
sys.path.insert(0, str(Path(__file__).with_name('makeelf')))
#print(sys.path)

os.environ['CASCADE_ENV_SOURCED'] = ''
os.environ['CASCADE_DATADIR'] = 'cascade-data'
os.environ['CASCADE_PATH_TO_FIGURES'] = 'cascade-figures'
os.environ['CASCADE_RISCV_BITWIDTH'] = '64'
os.environ['CASCADE_DESIGN_PROCESSING_ROOT'] = str(Path(__file__, '../design-processing').resolve())

design_name = 'boom'
descriptor = (881540, design_name, 5000017, 51, True)

#print('\033[33m[INFO] (a) calibrating the spike speed to estimate an expected upper bound of valid executions\033[m')
#from common.spike import calibrate_spikespeed
#calibrate_spikespeed()

#print('\033[33m[INFO] (b) finding which delegation bits are supported by the design\033[m')
#from common.profiledesign import profile_get_medeleg_mask
#profile_get_medeleg_mask(design_name)

print('\033[33m[INFO] emulation\033[m')
print('\033[33m' + '='*60 + '\033[m')

from collections import namedtuple
Descriptor = namedtuple('Descriptor', 'memsize design_name randseed nmax_bbs authorize_privileges')
descriptor = Descriptor(881540, 'boom', 5000017, 51, True)

#from cascade.fuzzfromdescriptor import fuzz_single_from_descriptor
#fuzz_single_from_descriptor(*descriptor, check_pc_spike_again=True)
#fuzz_single_from_descriptor(descriptor, check_pc_spike_again=True)
# ====

#from cascade.fuzzfromdescriptor import run_rtl
#fuzz_single_from_descriptor(*descriptor, check_pc_spike_again=True)
#gathered_times = run_rtl(descriptor, check_pc_spike_again=True)
# ====

# from cascade.fuzzfromdescriptor import gen_fuzzerstate_elf_expectedvals, runtest_simulator
#fuzzerstate, rtl_elfpath, finalregvals_spikeresol, *time_seconds_spent = \
#        gen_fuzzerstate_elf_expectedvals(*descriptor, check_pc_spike_again=True)
#runtest_simulator(fuzzerstate, rtl_elfpath, finalregvals_spikeresol)
# ====

import random
from cascade.fuzzerstate import FuzzerState
random.seed(descriptor.randseed)
fuzzerstate = FuzzerState(
        0x80000000,
        descriptor.design_name,
        descriptor.memsize,
        descriptor.randseed,
        descriptor.nmax_bbs,
        descriptor.authorize_privileges,
        nmax_instructions=None,
        nodependencybias=False)

from cascade.basicblock import gen_basicblocks
gen_basicblocks(fuzzerstate)

from cascade.spikeresolution import spike_resolution
expected_intregvals, expected_floatregvals = spike_resolution(fuzzerstate, check_pc_spike_again=True)
assert len(expected_intregvals) >= fuzzerstate.num_pickable_regs-1
assert fuzzerstate.design_has_fpu is True
assert len(expected_floatregvals) == fuzzerstate.num_pickable_floating_regs

from cascade.genelf import gen_elf_from_bbs
rtl_elfpath = gen_elf_from_bbs(
        fuzzerstate,
        is_spike_resolution=False,
        prefixname='rtl',
        test_identifier=fuzzerstate.instance_to_str(),
        start_addr=fuzzerstate.design_base_addr,
        )

from cascade.fuzzsim import runsim_verilator
num_instrs = sum(map(len, fuzzerstate.instr_objs_seq))
MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000
is_stop_successful, received_regvals = runsim_verilator(
            fuzzerstate.design_name,
            num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES,
            rtl_elfpath,
            fuzzerstate.num_pickable_regs-1,
            fuzzerstate.num_pickable_floating_regs)

print('\033[33m'+'='*30+'\033[m')
print(f'{descriptor=}')
print('\033[33m'+'='*30+'\033[m')
assert is_stop_successful is True
assert (L := tuple(map(len, received_regvals))) == (23, 9), L
