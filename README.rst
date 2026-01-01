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

    allocate store location for load/store (?)
    amount is 23 random in [1, 30]
    `fuzzerstate.num_store_locations`
    freepairs length 5 + 23
    store location length 23
    `fuzzerstate.memstorestate.store_locations`

generate basic blocks
    `fuzzerstate.bb_start_addr_seq`
    `fuzzerstate.instr_objs_seq`

    loop until reach `nmax_bbs` (eg: 51 - 1 = 50)
    or out of space for the next basic block

    during generating basic block,
    keep generating instructions if extra space left,
    otherwise, generating a branch/jump instruction

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

    if the last basic block cannot reach the final block,
    pop it out until one can

generate final block
    `fuzzerstate.final_bb`


命題:
(1) Spike 跑 ELF 究竟壞在哪裡?
(2) basic block 透過 Spike 算出了什麼?
(3) 本來預期跑完的結果為何? 對答案與找出錯誤的流程為何?


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PlaceholderProducerInstr0 -> rv32i_lui
PlaceholderProducerInstr1 -> rv32i_addi
PlaceholderPreConsumerInstr -> rv32i_and
PlaceholderConsumerInstr -> rv32i_xor

狀態機 (FSM) 為: lui -> addi -> and,and,xor
也就是: gen -> ready -> applied

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

每個 hardware design 可以有不同的 MEDELEG 設定.
in `fuzzer/common/profiledesign.py:__get_medeleg_mask`,
透過 csrrw 將 medeleg 設為全 1, 再透過 csrrwi 讀回來,
得知哪些 bit 是有效的.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

basic block 並不是很多種類, 只是有隨機成分.
basic block 幾乎都是在算下一個要跳去的位置在哪裡.

每個 basic block 只會被執行一次, 並沒有重複利用.

串起 basic block 的方法就只是 jump.
即使使用 branch (eg, bltu) 也是設計成必定跳到下一個規劃好的 basic block.

實作上 Cascade 在隨機位置產生隨機大小的 basic block 再依序串上,
事實上完全可以先產生隨機大小的 basic block 再排到隨機位置, 以減少空間浪費.
作者可能想令 *整個產生指令的過程都循序來*, 顯得很 *模擬*, 但事實上就只是慢.

jump 幾乎都是讀 register 以避免距離限制.
由於先確定了要 jump 的位址, register 的最終值也是確定的,
而 Cascade 設定成 "在 jump 之前必定有一次 xor", 所以會有額外的 "dependent register",
Cascade 實際跑一遍 Spike 到該位址去釐清當下 dependent register value,
再回頭透過 lui/addi 微調 register value.

所以 basic block 內至少需要四道指令: lui, addi, xor, control flow

basic block 內幾乎都在進行位址計算, 佐以一部分 ``& -1``.
穿插部分操作, 他們不影響 jump to next basic block.

load/store 使用的 memory address 有兩種:

1. 已經確定, 不會再因為要跑一遍 Spike 而改動其值 (eg, control flow, final block).
   這些可以用在 load.
   (這段 address 在程式碼內叫做 `blacklist`)

2. 預先保留最多 24 個 address.
   一旦一個 address 被使用, 下次被使用的機率會提升, 也就是儘量重複使用.
   (這段 address 在程式碼內叫做 `memstorestate`)

修正 final block 的 store location 要從 0x60000000 挪到例如 0x90000000,
但這樣的話 lui + addi 是不夠的, 至少需要再補上 slli + srli 修正 upper 32 bits.
