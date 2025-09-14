# Reference: ``cd /cascade-meta/fuzzer && python3 -u do_fuzzsingle.py``

# Python dependnecies::
#
#   pip install -U pip
#   pip install numpy
#   pip install git+https://github.com/flaviens/makeelf@finercontrol

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
#print(sys.path)

os.environ['CASCADE_ENV_SOURCED'] = ''
os.environ['CASCADE_DATADIR'] = 'cascade-data'
os.environ['CASCADE_PATH_TO_FIGURES'] = 'cascade-figures'
os.environ['CASCADE_RISCV_BITWIDTH'] = '64'
os.environ['CASCADE_DESIGN_PROCESSING_ROOT'] = str(Path(__file__, '../design-processing').resolve())

design_name = 'boom'
descriptor = (881540, design_name, 5000017, 51, True)

print('[INFO] (a) calibrating the spike speed to estimate an expected upper bound of valid executions')
from common.spike import calibrate_spikespeed
calibrate_spikespeed()

print('[INFO] (b) finding which delegation bits are supported by the design')
from common.profiledesign import profile_get_medeleg_mask
profile_get_medeleg_mask(design_name)

print('[INFO] emulation?')
from cascade.fuzzfromdescriptor import fuzz_single_from_descriptor
fuzz_single_from_descriptor(*descriptor, check_pc_spike_again=True)
