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


def dump_curr_bytearray(fuzzerstate, *, filename):
    assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    from collections import defaultdict
    addr_instrs = defaultdict(bytes)
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=False).to_bytes(4, 'little')
            for curr_byte_id, curr_byte in enumerate(curr_bytecode):
                curr_addr = bb_start_addr + 4*instr_id_in_bb + curr_byte_id # NO_COMPRESSED
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
                addr_instrs[curr_addr] = curr_byte

    assert fuzzerstate.ctxsv_bb == []

    for reg_data_id, reg_data_doubleword in enumerate(fuzzerstate.initial_reg_data_content):
        curr_bytecode = reg_data_doubleword.to_bytes(8, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.initial_reg_data_addr + 8*reg_data_id + curr_byte_id # doublewords therefore 8
            assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    final_block = fuzzerstate.final_bb
    for instr_id_in_bb, instr_obj in enumerate(final_block):
        curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=False).to_bytes(4, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.final_bb_base_addr + 4*instr_id_in_bb + curr_byte_id # NO_COMPRESSED
            assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    for word_id, word_content in enumerate(fuzzerstate.random_block_content4by4bytes):
        curr_bytecode = word_content.to_bytes(4, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.random_data_block_start_addr + 4*word_id + curr_byte_id # NO_COMPRESSED
            assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    curr_bytearray = bytearray(fuzzerstate.memsize) # Zero-filled
    for curr_addr, curr_byte in addr_instrs.items():
        curr_bytearray[curr_addr] = curr_byte
    curr_bytes = bytes(curr_bytearray)
    assert len(curr_bytes) % 4 == 0

    with open(filename, 'w') as fp:
        for i in range(0, len(curr_bytes), 4):
            print(hex(fuzzerstate.design_base_addr+i), '' if (v := ''.join(f'{v:02x}' for v in curr_bytes[i:i+4][::-1])) == '00000000' else v, file=fp)


def dump_sections(sections, entry_point, memory_size, *, filename):
    memory = bytearray(memory_size)
    for (address, alignment), section in sections:
        for value in section:
            bytes = value.to_bytes(alignment, 'little')
            memory[address:address+alignment] = bytes
            address += alignment

    with open(filename, 'w') as fp:
        for i in range(0, len(memory), 4):
            print(hex(entry_point+i), '' if (v := ''.join(f'{v:02x}' for v in memory[i:i+4][::-1])) == '00000000' else v, file=fp)


def to_sections(fuzzerstate) -> dict:
    def to_machine_code(instruction):
        return instruction.gen_bytecode_int(is_spike_resolution=False)

    # The first and generated basic blocks
    print(f'{list(map(hex, fuzzerstate.bb_start_addr_seq))=}')
    if fuzzerstate.nmax_bbs is not None:
        assert len(fuzzerstate.bb_start_addr_seq) == max(fuzzerstate.nmax_bbs, 1)
        assert len(fuzzerstate.instr_objs_seq) == max(fuzzerstate.nmax_bbs, 1)
    for address, instructions in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        yield (address, (alignment := 4)), map(to_machine_code, instructions)

    # XXX: register data?
    assert len(fuzzerstate.initial_reg_data_content) == fuzzerstate.num_pickable_regs - 1 + fuzzerstate.num_pickable_floating_regs
    yield (fuzzerstate.initial_reg_data_addr, (alignment := 8)), fuzzerstate.initial_reg_data_content

    # The final basic block
    yield (fuzzerstate.final_bb_base_addr, (alignment := 4)), map(to_machine_code, fuzzerstate.final_bb)

    # XXX: The random data block at the end?
    yield (fuzzerstate.random_data_block_start_addr, (alignment := 4)), fuzzerstate.random_block_content4by4bytes

    # XXX: Maybe it's used for reproducing?
    assert fuzzerstate.ctxsv_bb == []


def to_elf(sections, entry_point, memory_size, *, filename):
    memory = bytearray(memory_size)
    for (address, alignment), section in sections:
        for value in section:
            Bs = value.to_bytes(alignment, 'little')
            memory[address:address+alignment] = Bs
            address += alignment

    #from common.bytestoelf import gen_elf
    #gen_elf(bytes(memory), entry_point, entry_point, filename, is_64bit=True)

    from makeelf.elf import ELF, EM, ELFDATA, SHF
    elf = ELF(e_machine=EM.EM_RISCV, e_data=ELFDATA.ELFDATA2LSB, e_entry=entry_point)
    section_id = elf.append_section(
        '.text.init',
        bytes(memory),
        entry_point,
        sh_flags=SHF.SHF_ALLOC|SHF.SHF_EXECINSTR,  # 0x2|0x4, loadable and executable
        sh_addralign=4,
        )
    elf.append_segment(section_id, addr=entry_point, p_offset=0xe2)  # XXX: Very hacky, we hardcode the section offset.
    with open(filename, 'wb') as fp:
        fp.write(bytes(elf))

    import subprocess as sp
    sp.run(f'riscv64-unknown-elf-objcopy --change-section-address .text.init={hex(entry_point)} -I elf32-littleriscv -O elf64-littleriscv {filename}', shell=True, check=True)


from cascade.fuzzerstate import FuzzerState as FuzzerStateBase
from cascade.basicblock import gen_basicblocks
class FuzzerState(FuzzerStateBase):
    randseed = 5000017
    nmax_bbs = 51
    #nmax_bbs = 0
    #nmax_bbs = None
    nmax_instructions = None  # XXX: looks unused
    memsize = 881540  # 0xd7384
    memsize = 0x1000
    memsize = 0x10000

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

#print('\033[33m[INFO] gen_elf_from_bbs\033[m')
#from cascade.genelf import gen_elf_from_bbs
#rtl_elfpath = gen_elf_from_bbs(
#        fuzzerstate,
#        is_spike_resolution=False,
#        prefixname='rtl',
#        test_identifier=fuzzerstate.instance_to_str(),
#        start_addr=fuzzerstate.design_base_addr,
#        )
print('\033[33m[INFO] to ELF\033[m')
entry_point = fuzzerstate.design_base_addr
dump_curr_bytearray(fuzzerstate, filename='out.txt')
dump_sections(to_sections(fuzzerstate), entry_point, fuzzerstate.memsize, filename='gen.txt')
to_elf(to_sections(fuzzerstate), entry_point, fuzzerstate.memsize,
       filename=f'rtl_{fuzzerstate.memview.memsize}_{fuzzerstate.design_name}_{fuzzerstate.randseed}_{fuzzerstate.nmax_bbs}.elf')

print('\033[32m================\033[m')
