#!/usr/bin/env python3
"""
run_sweep.py <N> — coordinator; processes N source files from queue.txt.
Called by run_sweep.sh. Run via: bash cyber/run_sweep.sh <N>

Pipeline per file:
  1. scout scans source → "skip" or FINDING blocks
  2. tester receives source + findings → writes test .py blocks
  3. each test is run via cyber/run.sh; ASan/UBSan hits are confirmed
"""

import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

CYBER = Path(__file__).parent.resolve()
REPO = (CYBER / "..").resolve()
STATE = CYBER / "sweep"
CONFIRMED = STATE / "confirmed"
CONFIRMED.mkdir(parents=True, exist_ok=True)

_log_file = open(STATE / "sweep_log.txt", "a", buffering=1)


def log(msg: str) -> None:
    print(msg, flush=True)
    print(msg, file=_log_file, flush=True)

ASAN_PATTERN = re.compile(
    r"AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow"
    r"|use-after-free|double-free|SEGV|UBSan|runtime error",
    re.IGNORECASE,
)

stopping = False


def handle_sigint(sig, frame):
    global stopping
    log("\n[sweep] CTRL-C — finishing current file then stopping.")
    stopping = True


signal.signal(signal.SIGINT, handle_sigint)


# ── queue helpers ─────────────────────────────────────────────────────────────

def slug_for(src: str) -> str:
    return src.replace("/", "_")


def pop_file(queue: Path) -> str | None:
    lines = queue.read_text().splitlines()
    if not lines:
        return None
    entry = lines[0]
    queue.write_text("\n".join(lines[1:]) + ("\n" if len(lines) > 1 else ""))
    return entry


# ── python block extractor ────────────────────────────────────────────────────

def extract_python_blocks(text: str, slug: str, status_dir: Path) -> list[Path]:
    """Parse ```python ... ``` fences from *text*.

    Each block is written to a file.  If the first line of the block is a
    comment "# <path>", that path is used verbatim; otherwise the file is
    named <slug>_test_N.py in status_dir.
    """
    paths: list[Path] = []
    n = 0
    in_block = False
    block_lines: list[str] = []

    for line in text.splitlines():
        if not in_block:
            if line.rstrip() == "```python":
                in_block = True
                block_lines = []
            continue
        if line.rstrip() == "```":
            in_block = False
            n += 1
            block_text = "\n".join(block_lines) + "\n"
            first = block_lines[0] if block_lines else ""
            if first.startswith("# "):
                out_path = Path(first[2:].strip())
            else:
                out_path = status_dir / f"{slug}_test_{n}.py"
            out_path.write_text(block_text)
            paths.append(out_path)
            continue
        block_lines.append(line)

    return paths


# ── per-file processing ───────────────────────────────────────────────────────

def run_claude(model: str, system_prompt: str, user_msg: str) -> str:
    cmd = [
        "claude",
        "--model", model,
        "--print",
        "--system-prompt", system_prompt,
    ]
    result = subprocess.run(
        cmd,
        input=user_msg,
        capture_output=True,
        text=True,
    )
    return (result.stdout or "") + (result.stderr or "")


def process_file(src: str) -> None:
    slug = slug_for(src)
    status_dir = STATE / "status"
    status_file = status_dir / f"{slug}.md"
    abs_src = REPO / src

    log(f"[sweep] processing {src}")

    if not abs_src.exists():
        log(f"[sweep] {src} -> skip (file not found)")
        return

    src_content = abs_src.read_text(errors="replace")
    scan_prompt = (CYBER / "scan_prompt.txt").read_text()
    exploit_prompt = (CYBER / "exploit_prompt.txt").read_text()

    # ── phase 1: scout scan ──────────────────────────────────────────────────
    scan_out = run_claude(
        model="claude-sonnet-4-6",
        system_prompt=scan_prompt,
        user_msg=f"File: {src}\n\n{src_content}",
    )

    verdict = scan_out.strip().lower().replace(" ", "").replace("\n", "")
    if verdict == "skip":
        if status_file.exists():
            status_file.unlink()
        log(f"[sweep] {src} -> skip")
        return

    log(f"[sweep] {src} -> findings found, handing to tester")

    # ── phase 2: tester test harness ────────────────────────────────────────────
    tester_user = (
        f"File: {src}\n"
        f"Repo root: {REPO}\n"
        f"Status dir: {status_dir}/\n"
        f"SLUG: {slug}\n"
        f"(Test files should be named {slug}_test_1.py, _test_2.py, etc.\n"
        f" Write them to {status_dir}/)\n\n"
        f"--- SOURCE ---\n{src_content}\n\n"
        f"--- SCANNER FINDINGS ---\n{scan_out}"
    )
    tester_out = run_claude(
        model="claude-sonnet-4-6",
        system_prompt=exploit_prompt,
        user_msg=tester_user,
    )

    # ── write combined status file ────────────────────────────────────────────
    status_file.write_text(
        f"# {src}\n\n"
        f"## Scanner findings\n\n{scan_out}\n\n"
        f"## Test harnesses\n\n{tester_out}\n"
    )

    # ── extract and run test files ────────────────────────────────────────────
    test_files = extract_python_blocks(tester_out, slug, status_dir)
    any_confirmed = False

    for test_py in test_files:
        if not test_py.exists():
            continue
        log(f"[sweep]   running {test_py}")

        run_result = subprocess.run(
            ["bash", "cyber/run.sh", str(test_py)],
            capture_output=True,
            text=True,
            cwd=str(REPO),
        )
        run_out = run_result.stdout + run_result.stderr

        if ASAN_PATTERN.search(run_out):
            result_label = "CONFIRMED"
            any_confirmed = True
            confirmed_py = CONFIRMED / f"curl_{slug}.py"
            shutil.copy(test_py, confirmed_py)
            log(f"[sweep]   *** CONFIRMED — saved to {confirmed_py} ***")
        elif re.search(r"inconclusive|unknown", run_out, re.IGNORECASE):
            result_label = "INCONCLUSIVE"
        else:
            result_label = "BLOCKED"

        with open(status_file, "a") as f:
            f.write(
                f"\n### Run: {test_py.name} — {result_label}\n\n"
                f"```\n{run_out}\n```\n"
            )

    # ── update hits.md ────────────────────────────────────────────────────────
    label = "CONFIRMED" if any_confirmed else "attempted"
    with open(STATE / "hits.md", "a") as f:
        f.write(f"- {label} [{src}]({status_file})\n")

    log(f"[sweep] {src} -> done (confirmed={int(any_confirmed)})")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        print("Usage: python3 run_sweep.py <N>", file=sys.stderr)
        sys.exit(1)

    batch = int(sys.argv[1])
    queue = STATE / "queue.txt"

    if not queue.exists():
        print("queue.txt not found — run bash cyber/init_sweep.sh first",
              file=sys.stderr)
        sys.exit(1)

    (STATE / "status").mkdir(exist_ok=True)

    log(f"[sweep] Starting batch of {batch} file(s), single-threaded")
    processed = 0

    while processed < batch:
        if stopping:
            break
        src = pop_file(queue)
        if src is None:
            log("[sweep] Queue empty.")
            break
        process_file(src)
        processed += 1

    remaining = sum(1 for l in queue.read_text().splitlines() if l.strip()) \
        if queue.exists() else "?"
    log_path = STATE / "sweep_log.txt"
    done_count = sum(1 for l in log_path.read_text().splitlines() if l.startswith("[sweep] processing")) \
        if log_path.exists() else "?"
    hits_file = STATE / "hits.md"
    confirmed_count = sum(
        1 for l in hits_file.read_text().splitlines() if l.startswith("- CONFIRMED")
    ) if hits_file.exists() else 0

    log(
        f"\n[sweep] Done. Processed={processed}  Total done={done_count}"
        f"  Confirmed={confirmed_count}  Remaining={remaining}"
    )


if __name__ == "__main__":
    main()
