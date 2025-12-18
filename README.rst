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

generate initial basic block and register data
    `cascade.initialblock.gen_initial_basic_block`

    start address (offset):
        0x80000000

        `fuzzerstate.bb_start_addr_seq`
        [ 0x0 ]

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

        The last instruction is `jal`,
        which jumps to the next basic block 0x7f30
        recorded in `fuzzerstate.next_bb_addr`

    register data:
        `fuzzerstate.initial_reg_data_content`
        [ ... ](length 32 = 24 + 9 - 1)

    backup weight, state, and producer ID (?) of integer registers
        `fuzzerstate.save_reg_state`

        weight
            0.2 for x15
            [0.8/23, 0.8/23, ...,  0.8/23, 0.2, 0.8/23, ..., 0.8/23]

        state
            FREE for all

        producer ID (?)
            NaN for all

miscellaneous
    allocate [0x7f30, +0x18)
    freepairs [ [0x224, 0x7f30), [0x7f48, 0x10000) ]

    allocate random data at [0xd794, 0xd7b0)
    freepairs [ [0x224, 0x7f30), [0x7f48, 0xd794), [0xd7b0, 0x10000) ]
    length is 7 * 4 = 28 = 0x1c, random in [12, 64)
    generate random data
    `fuzzerstate.random_block_content4by4bytes`

    allocate final basic block at [ 0x2d7c, +(((25+14) * 2 + 9) * 4)) )
    freepairs [ [0x224, 0x2d7c), [0x32ec, 0x7f30), [0x7f48, 0xd794), [0xd7b0, 0x10000) ]

    allocate context saver [0x5674, +0xedc)
    freepairs [ [0x224, 0x2d7c), [0x32ec, 0x5674), [0x6550, 0x7f30), [0x7f48, 0xd794), [0xd7b0, 0x10000) ]
    no data
    `fuzzerstate.ctxsv_bb`

    allocate store location (?)
    amount is 23 random in [1, 30]
    `fuzzerstate.num_store_locations`
    freepairs length 5 + 23
    store location length 23
    `fuzzerstate.memstorestate.store_locations`

generate basic blocks
    loop until reach `nmax_bbs` (eg: 51 - 1 = 50)
    or out of space for the next basic block

    during generating basic block,
    keep generating instructions if extra space left,
    otherwise, generating a J instruction

    .. code:: python

        for _ in range(1, 51+1):
            basicblock_address = address_to_jump
            allocate_space(length=0x18)
            basicblock = []
            while space_left(start=basicblock_address, extra=0x18+4):
                instructions = ...(...)  # may include `address_to_jump`
                allocate_space(start=basicblock_address+len(basicblock)*4, length=len(instructions)*4)
                basicblock.extend(instructions)
                if hasattr(instructions, 'address_to_jump'):
                    address_to_jump = getattr(instructions, 'address_to_jump')
                    break
            else:
                instructions = ...(...)  # include `address_to_jump`
                allocate_space(start=basicblock_address+len(basicblock)*4, length=len(instructions)*4)
                basicblock.extend(instructions)
                address_to_jump = getattr(instructions, 'address_to_jump')

            yield basicblock

            if address_to_jump is None:
                break  # out of space

generate final block
    `fuzzerstate.final_bb`
