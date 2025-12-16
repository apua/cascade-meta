See `hacking.py <./hacking.py>`_

initialize properties
    `fuzzerstate.reset`

    freepairs:
        `fuzzerstate.memview.freepairs`
        [ [0x0, 0x10000) ]

    instruction objects:
        `fuzzerstate.instr_objs_seq`
        []

    pickable registers:
        `fuzzerstate.num_pickable_regs`
        24

        `fuzzerstate.num_pickable_floating_regs`
        9

generate initial basic block
    `cascade.initialblock.gen_initial_basic_block`

    start address (offset):
        0x80000000

    offset of register data:
        `fuzzerstate.initial_reg_data_addr`
        `fuzzerstate.initial_block_data_start`
        0x120

        `fuzzerstate.initial_block_data_end`
        0x220

    freepairs:
        [ [0x224, 0x10000) ]

    instruction objects:
        `fuzzerstate.instr_objs_seq`
        [ [ ... ](length 72) ]

    register data:
        `fuzzerstate.initial_reg_data_content`
        [ ... ](length 32 = 24 + 9 - 1)

    next basic block address:
        `fuzzerstate.next_bb_addr`
        random address in [0x224, 0x100000) regardless memory size
        0x7f30
