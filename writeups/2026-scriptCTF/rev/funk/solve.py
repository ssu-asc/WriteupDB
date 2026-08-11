"""
scriptCTF 2026 - rev/funk

funk is a ~28KB brainfuck program with no loop-body comments and a trailing
"+[]" that spins forever -- so you can't just brute force whole-flag guesses
and wait for it to "finish". Instead we compile the BF to Python (collapsing
runs of +/-/</> into single ops) and add a per-loop iteration counter, then
use that as a side channel: for every candidate flag byte we can see exactly
how many times each of the 126 loops fired.

Feeding an all-zero input showed the same 31 "," reads every time and always
ended up spinning in the very last loop, no matter what was typed -- that
loop is just the program's unconditional halt, not a failure trap. But when
we set exactly one input byte to a marker value and diffed the loop counters
against the all-zero baseline, each of the first 31 input positions lit up
exactly ONE loop each, and that loop's iteration count was always
(base_constant + input_byte) mod 256. That "count" loop is a data-move
("[-<->]"-style) idiom, so its iteration count is literally the value being
carried out of the addition -- the real check is whether that value is 0.

So each position independently wants input_byte = (256 - base_constant) % 256.
We recover base_constant for every position by reading the loop counters
straight off the all-zero run (input=0 makes count == base_constant), then
solve for the byte, and finally confirm the guess by re-running the full
program and checking every one of those 31 loops now reads exactly 0.
"""
import pickle
import sys

FUNK_PATH = "funk"


def load_code():
    raw = open(FUNK_PATH).read()
    return "".join(c for c in raw if c in "+-<>[],.")


def compile_bf(code, limit=3_000_000):
    """Compile BF to a Python function with a per-loop hit counter."""
    lines = [
        "def run(tape, inp):",
        " p = len(tape)//2",
        " out = bytearray()",
        " i = 0",
        " n = len(inp)",
        " steps = 0",
        f" LIMIT = {limit}",
        " rcount = 0",
        " wcount = 0",
    ]

    tokens = []
    i = 0
    while i < len(code):
        c = code[i]
        if c in "+-<>":
            j = i
            while j < len(code) and code[j] == c:
                j += 1
            tokens.append((c, j - i))
            i = j
        else:
            tokens.append((c, 1))
            i += 1

    total_loops = sum(1 for c, _ in tokens if c == "[")
    lines.append(f" counts = [0]*{total_loops + 1}")

    indent = 1
    loop_id = 0
    for c, cnt in tokens:
        pad = " " * indent
        if c == "+":
            lines.append(f"{pad}tape[p] = (tape[p] + {cnt}) & 0xff")
        elif c == "-":
            lines.append(f"{pad}tape[p] = (tape[p] - {cnt}) & 0xff")
        elif c == ">":
            lines.append(f"{pad}p += {cnt}")
        elif c == "<":
            lines.append(f"{pad}p -= {cnt}")
        elif c == ".":
            lines.append(f"{pad}out.append(tape[p]); wcount += 1")
        elif c == ",":
            lines.append(f"{pad}tape[p] = inp[i] if i < n else 0")
            lines.append(f"{pad}i += 1; rcount += 1")
        elif c == "[":
            loop_id += 1
            lid = loop_id
            lines.append(f"{pad}while tape[p] != 0:")
            indent += 1
            pad2 = " " * indent
            lines.append(f"{pad2}counts[{lid}] += 1")
            lines.append(f"{pad2}steps += 1")
            lines.append(f"{pad2}if steps > LIMIT: return out, rcount, wcount, counts")
        elif c == "]":
            indent -= 1

    lines.append(" return out, rcount, wcount, counts")
    return "\n".join(lines)


def make_runner(code):
    src = compile_bf(code)
    ns = {}
    exec(compile(src, "<funk>", "exec"), ns)
    run = ns["run"]

    def try_input(inp: bytes, tape_size=200_000):
        tape = bytearray(tape_size)
        out, rc, wc, counts = run(tape, inp)
        return bytes(out), rc, wc, counts

    return try_input


def main():
    code = load_code()
    try_input = make_runner(code)

    N = 38          # comfortably more than the flag needs
    MARK = 111

    base_out, base_rc, base_wc, base_counts = try_input(b"")
    print(f"[baseline] reads={base_rc} writes={base_wc}")

    flag_bytes = {}   # pos -> byte
    check_loops = {}  # pos -> loop id that must read 0 on success
    for pos in range(N):
        probe = bytearray(N)
        probe[pos] = MARK
        _, _, _, counts = try_input(bytes(probe))
        last = len(counts) - 1
        changed = [
            lid for lid, c in enumerate(counts)
            if c != base_counts[lid] and lid != last  # skip the trailing halt loop
        ]
        if not changed:
            continue  # position isn't consumed by the checker at all
        lid = changed[0]
        base_const = base_counts[lid]
        flag_bytes[pos] = (256 - base_const) % 256
        check_loops[pos] = lid

    flag = "".join(chr(flag_bytes[p]) for p in sorted(flag_bytes))
    print("recovered flag:", flag)

    # sanity check: with the recovered flag, every one of those loops
    # should now fire exactly zero times
    _, _, _, counts = try_input(flag.encode())
    ok = all(counts[lid] == 0 for lid in check_loops.values())
    print("all checks satisfied:", ok)


if __name__ == "__main__":
    main()
