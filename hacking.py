# cd /cascade-meta/fuzzer && python3 -u do_fuzzsingle.py

# pip install -U pip
# pip install numpy
# pip install git+https://github.com/flaviens/makeelf@finercontrol

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name('fuzzer')))
#print(sys.path)

#import do_fuzzsingle
os.environ['CASCADE_ENV_SOURCED'] = ''
os.environ['CASCADE_DATADIR'] = 'cascade-data'
os.environ['CASCADE_PATH_TO_FIGURES'] = 'cascade-figures'
os.environ['CASCADE_RISCV_BITWIDTH'] = '64'
os.environ['CASCADE_DESIGN_PROCESSING_ROOT'] = str(Path(__file__, '../design-processing').resolve())

from cascade.fuzzfromdescriptor import fuzz_single_from_descriptor
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed
from cascade.toleratebugs import tolerate_bug_for_eval_reduction

design_name = 'boom'
descriptor = (881540, design_name, 5000017, 51, True)

# tolerate_bug_for_eval_reduction(design_name)

print('[INFO] (a) calibrating the spike speed to estimate an expected upper bound of valid executions')
calibrate_spikespeed()

print('[INFO] (b) finding which delegation bits are supported by the design')
profile_get_medeleg_mask(design_name)

print('[INFO] emulation?')
fuzz_single_from_descriptor(*descriptor, check_pc_spike_again=True)
