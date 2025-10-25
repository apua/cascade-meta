#!/usr/bin/env python3
"""
Requirements::

    pip install -U pip
    pip install numpy tqdm filelock git+https://github.com/flaviens/makeelf@finercontrol
    module load sifive/freedom-tools/toolsuite
    module load dtc

Run::

    python fuzzer/generate_elfs.py --design kronos
"""

import argparse
import os
import sys
import shutil
from pathlib import Path
import multiprocessing as mp


def _worker_generate(args_tuple):
    # Unpack
    i, design, outdir, descriptor = args_tuple
    memsize, _, randseed, nmax_bbs, authorize_priv = descriptor

    # Lazy imports inside worker to honor CASCADE_DATADIR set in parent
    from cascade.fuzzfromdescriptor import gen_fuzzerstate_elf_expectedvals

    # Patch Spike path in worker process
    import subprocess
    original_subprocess_run = subprocess.run
    original_spike_path = "/home/hsiangchiah/bin/bin/spike"

    def patched_subprocess_run(args, *pargs, **kwargs):
        if isinstance(args, (list, tuple)) and len(args) > 0 and args[0] == 'spike':
            args = list(args)
            args[0] = original_spike_path
        return original_subprocess_run(args, *pargs, **kwargs)

    # Apply the patch in worker
    subprocess.run = patched_subprocess_run

    fuzzerstate, elfpath, _expected, _t1, _t2, _t3 = gen_fuzzerstate_elf_expectedvals(
        memsize, design, randseed, nmax_bbs, authorize_priv, check_pc_spike_again=False
    )

    # Move artifacts to outdir (match analyzeelfs/genmanyelfs.py)
    dst_elf = os.path.join(outdir, f"{design}_{i}.elf")
    shutil.move(elfpath, dst_elf)

    with open(os.path.join(outdir, f"{design}_{i}_finaladdr.txt"), "w") as f:
        f.write(hex(fuzzerstate.final_bb_base_addr))

    num_instrs = len(fuzzerstate.final_bb)
    for bb in fuzzerstate.instr_objs_seq:
        num_instrs += len(bb)
    with open(os.path.join(outdir, f"{design}_{i}_numinstrs.txt"), "w") as f:
        f.write(hex(num_instrs))

    with open(os.path.join(outdir, f"{design}_{i}_tuple.txt"), "w") as f:
        f.write('(' + ', '.join(map(str, [memsize, design, randseed, nmax_bbs, authorize_priv])) + ')')

    return True


def main():
    parser = argparse.ArgumentParser(description="Generate Cascade ELF files (no RTL)")
    parser.add_argument("--design", required=True, help="Design name (e.g. rocket, ibex, cva6, boom, pulpissimo, kronos)")
    parser.add_argument("--outdir", default="./elfs", help="Output directory for generated ELF files (default: ./elfs)")
    parser.add_argument("--num", type=int, default=10, help="Number of ELFs to generate (default: 10)")
    parser.add_argument("--jobs", type=int, default=int(os.getenv("CASCADE_JOBS", str(os.cpu_count() or 1))), help="Parallel jobs (default: CASCADE_JOBS or CPU count)")
    parser.add_argument("--tmpdir", default=None, help="Override CASCADE_DATADIR (writable temp dir). If not set, uses $CASCADE_DATADIR or ./cascade-tmp")
    args = parser.parse_args()

    # Basic env checks similar to other scripts
    if "CASCADE_ENV_SOURCED" not in os.environ:
        print("[ERROR] Cascade environment not sourced. Please 'source cascade-meta/env.sh' before running.", file=sys.stderr)
        sys.exit(1)

    if not os.getenv("CASCADE_DESIGN_PROCESSING_ROOT"):
        print("[ERROR] CASCADE_DESIGN_PROCESSING_ROOT not set. Ensure env.sh and design repos are set up.", file=sys.stderr)
        sys.exit(1)

    # Ensure CASCADE_DATADIR is a writable directory BEFORE importing modules that create it
    chosen_tmp = args.tmpdir or os.getenv("CASCADE_DATADIR") or str(Path.cwd() / "cascade-tmp")
    try:
        Path(chosen_tmp).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        # Fallback to a local tmp if the provided path is not writable
        fallback_tmp = str(Path.cwd() / "cascade-tmp")
        print(f"[WARN] Unable to create tmpdir '{chosen_tmp}' ({e}). Falling back to '{fallback_tmp}'.")
        chosen_tmp = fallback_tmp
        Path(chosen_tmp).mkdir(parents=True, exist_ok=True)
    os.environ["CASCADE_DATADIR"] = chosen_tmp

    # Ensure we can import generator utilities
    fuzzer_dir = Path(__file__).resolve().parent
    if str(fuzzer_dir) not in sys.path:
        sys.path.insert(0, str(fuzzer_dir))

    try:
        from analyzeelfs.genmanyelfs import gen_new_test_instance  # just for descriptor
        from common.spike import calibrate_spikespeed
        import common.spike
    except Exception as e:
        print(f"[ERROR] Failed to import generator utilities: {e}", file=sys.stderr)
        sys.exit(1)

    # Patch Spike path to use the specified spike binary
    original_spike_path = "/home/hsiangchiah/bin/bin/spike"

    def patched_run_spike_command(spike_shell_command, *args, **kwargs):
        """Patch spike command to use the specified path"""
        if isinstance(spike_shell_command, (list, tuple)) and len(spike_shell_command) > 0:
            # Replace 'spike' with full path
            cmd_list = list(spike_shell_command)
            if cmd_list[0] == 'spike':
                cmd_list[0] = original_spike_path
            spike_shell_command = cmd_list

        import subprocess
        return subprocess.run(spike_shell_command, *args, **kwargs)

    # Replace subprocess.run calls in spike module
    import subprocess
    original_subprocess_run = subprocess.run

    def patched_subprocess_run(args, *pargs, **kwargs):
        if isinstance(args, (list, tuple)) and len(args) > 0 and args[0] == 'spike':
            args = list(args)
            args[0] = original_spike_path
        return original_subprocess_run(args, *pargs, **kwargs)

    # Apply the patch
    subprocess.run = patched_subprocess_run

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    # Prepare workloads (avoid profile_get_medeleg_mask to skip RTL usage)
    import random
    random.seed(0)
    descriptors = [gen_new_test_instance(args.design, i, True) for i in range(args.num)]

    # Calibrate Spike once (no RTL involved)
    calibrate_spikespeed()

    print(f"[INFO] Generating {args.num} ELF(s) for design '{args.design}' → {outdir} using {args.jobs} job(s) (no RTL)...")

    workloads = [(i, args.design, str(outdir), descriptors[i]) for i in range(args.num)]
    if args.jobs and args.jobs > 1:
        with mp.Pool(args.jobs) as pool:
            for _ in pool.imap_unordered(_worker_generate, workloads):
                pass
    else:
        for w in workloads:
            _worker_generate(w)

    print("[INFO] Done.")


if __name__ == "__main__":
    main()
