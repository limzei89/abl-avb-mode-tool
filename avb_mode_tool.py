"""Read-only, evidence-based ARM64 ABL AVB mode classifier. Python >= 3.8."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import ARM64_OP_IMM
except ImportError:
    print('capstone is required: python -m pip install "capstone>=5,<6"', file=sys.stderr)
    sys.exit(2)


def u32(b, p):
    return struct.unpack_from('<I', b, p)[0]


class Image:
    def __init__(self, path):
        self.original = Path(path).read_bytes()
        self.sha256 = hashlib.sha256(self.original).hexdigest()
        data = self.original
        if data.startswith(b'\x7fELF'):
            payloads = set()
            # Known Qualcomm ABL container: LZMA-alone begins near 0x1000.
            # Refuse other containers instead of interpreting compressed bytes as code.
            for p in range(0x1000, min(len(data), 0x2000)):
                if data[p] != 0x5d:
                    continue
                try:
                    dec = lzma.LZMADecompressor()
                    expanded = dec.decompress(data[p:], max_length=16 * 1024 * 1024)
                    if dec.eof and b'PE\0\0' in expanded:
                        payloads.add(expanded)
                except lzma.LZMAError:
                    pass
            if len(payloads) != 1:
                raise ValueError('Unsupported/ambiguous ELF compression (expected one LZMA PE)')
            data = payloads.pop()
        candidates = []
        for m in re.finditer(b'MZ', data):
            pe = data[m.start():]
            if len(pe) < 64:
                continue
            h = u32(pe, 60)
            if h + 24 > len(pe) or pe[h:h + 4] != b'PE\0\0':
                continue
            if struct.unpack_from('<H', pe, h + 4)[0] != 0xaa64:
                continue
            count = struct.unpack_from('<H', pe, h + 6)[0]
            opt_size = struct.unpack_from('<H', pe, h + 20)[0]
            opt = h + 24
            if opt_size < 32 or opt + opt_size + count * 40 > len(pe):
                continue
            if struct.unpack_from('<H', pe, opt)[0] != 0x20b:
                continue
            sections = []
            for j in range(count):
                q = opt + opt_size + j * 40
                vs, va, size, raw = struct.unpack_from('<IIII', pe, q + 8)
                flags = u32(pe, q + 36)
                if raw + size > len(pe):
                    raise ValueError('Truncated PE section')
                sections.append((va, raw, size, flags))
            candidates.append((pe, sections, struct.unpack_from('<Q', pe, opt + 24)[0]))
        if len(candidates) != 1:
            raise ValueError('Expected one ARM64 PE32+ image, found %d' % len(candidates))
        self.pe, self.sections, self.base = candidates[0]
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True
        md.skipdata = True
        self.code = {}
        for va, raw, size, flags in self.sections:
            if flags & 0x20000000:
                for ins in md.disasm(self.pe[raw:raw + size], va):
                    if ins.id:
                        self.code[ins.address] = ins

    def raw(self, va):
        for start, raw, size, _ in self.sections:
            if start <= va < start + size:
                return raw + va - start
        raise ValueError('Unmapped RVA 0x%x' % va)

    def rva(self, raw_offset):
        for start, raw, size, _ in self.sections:
            if raw <= raw_offset < raw + size:
                return start + raw_offset - raw
        return None

    def span(self, start, end):
        return [self.code[p] for p in range(start, end, 4) if p in self.code]

    def evidence(self, start, end):
        return ['0x%08x  %-10s %s' % (i.address, i.mnemonic, i.op_str)
                for i in self.span(start, end)]


def target(ins):
    if ins.mnemonic in ('bl', 'b') and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
        return ins.operands[0].imm
    return None


def xrefs(image, wanted):
    """Resolve ADR or short ADRP/ADD sequences, allowing intervening independent instructions."""
    found = []
    for pc, ins in image.code.items():
        if ins.mnemonic == 'adr' and ins.operands[1].imm in wanted:
            found.append((pc, ins.operands[1].imm, ins.reg_name(ins.operands[0].reg)))
        if ins.mnemonic != 'adrp':
            continue
        reg, page = ins.reg_name(ins.operands[0].reg), ins.operands[1].imm
        for following in image.span(pc + 4, pc + 32):
            ops = following.operands
            if (following.mnemonic == 'add' and len(ops) == 3 and
                    following.reg_name(ops[1].reg) == reg and ops[2].type == ARM64_OP_IMM):
                value = page + (ops[2].imm << ops[2].shift.value)
                if value in wanted:
                    found.append((following.address, value, following.reg_name(ops[0].reg)))
            if following.mnemonic in ('bl', 'blr', 'b', 'ret'):
                break
            if following.operands and following.operands[0].type == 1:
                written = following.reg_name(following.operands[0].reg)
                if written == reg:
                    break
    return sorted(set(found))


def epilogue_preserves_w0(image, address):
    instructions = image.span(address, address + 24)
    for i in instructions:
        if i.mnemonic in ('ret', 'retab'):
            return True
        if i.mnemonic not in ('add', 'ldp', 'ldr', 'autiasp', 'autibsp', 'nop'):
            return False
        if i.op_str.split(',')[0] in ('x0', 'w0'):
            return False
    return False


def selector(image, address):
    """Recognize the verified bool-to-0/2 wrapper, not arbitrary ARM64 functions."""
    seq = []
    for pc in range(address, address + 0xc0, 4):
        i = image.code.get(pc)
        if i is None:
            break
        seq.append(i)
        if i.mnemonic in ('ret', 'retab', 'b'):
            break
    if len(seq) < 4:
        return None
    for j in range(1, len(seq) - 1):
        t, c = seq[j], seq[j + 1]
        if not (t.mnemonic == 'tst' and t.op_str == 'w0, #0xff' and
                c.mnemonic == 'cset' and c.op_str.endswith(', ne')):
            continue
        if seq[j - 1].mnemonic == 'bl':
            source = target(seq[j - 1])
        else:
            # The known wrapper loads its stack cookie between BL and TST.
            calls = [i for i in seq[:j] if i.mnemonic == 'bl']
            if not calls:
                continue
            source = target(calls[-1])
            between = seq[seq.index(calls[-1]) + 1:j]
            if any(i.mnemonic not in ('adrp', 'ldr') or i.op_str.startswith(('w0,', 'x0,'))
                   for i in between):
                continue
        reg = c.op_str.split(',')[0]
        shift = next((i for i in seq[j + 2:] if i.mnemonic == 'lsl' and
                      i.op_str == 'w0, %s, #1' % reg), None)
        if shift is None:
            continue
        middle = [i for i in seq[j + 2:] if i.address < shift.address]
        # Permit only the known cookie check; reject unmodelled register writes/calls.
        if any(i.mnemonic not in ('add', 'ldr', 'cmp', 'b.ne') or
               (i.mnemonic in ('add', 'ldr') and i.op_str.split(',')[0] in (reg, 'w0', 'x0'))
               for i in middle):
            continue
        for branch in middle:
            if branch.mnemonic == 'b.ne':
                dest = branch.operands[0].imm
                failure = image.code.get(dest)
                # Only accept the outward cookie-failure call, never a second return path.
                if dest <= shift.address or failure is None or failure.mnemonic != 'bl':
                    break
        else:
            after = image.code.get(shift.address + 4)
            if after and ((after.mnemonic in ('ret', 'retab')) or
                          (after.mnemonic == 'b' and epilogue_preserves_w0(image, target(after)))):
                return {'kind': 'SELECT_0_OR_2', 'selector_rva': hex(address),
                        'condition_function_rva': hex(source), 'values': [0, 2],
                        'evidence': image.evidence(address, after.address + 4)}
    # Constant getters are accepted only as small straight-line functions.
    if len(seq) <= 8 and all(i.mnemonic in ('bti', 'nop', 'mov', 'ret', 'b') for i in seq):
        writes = [i for i in seq if i.mnemonic == 'mov']
        if len(writes) == 1 and writes[0].op_str == 'w0, #2':
            last = seq[-1]
            if last.mnemonic == 'ret' or (last.mnemonic == 'b' and epilogue_preserves_w0(image, target(last))):
                return {'kind': 'FIXED_2', 'selector_rva': hex(address), 'values': [2],
                        'evidence': image.evidence(address, last.address + 4)}
    return None


def analyze(path):
    image = Image(path)
    strings = {}
    for m in re.finditer(rb'AVB version %d\x00|AVB version %d\n\x00', image.pe):
        va = image.rva(m.start())
        if va is not None:
            strings[va] = m[0].rstrip(b'\0').decode('ascii')
    logs, findings = [], []
    for pc, string, arg in xrefs(image, strings):
        if arg != 'x1':
            continue
        later = image.span(pc + 4, pc + 40)
        log_call = next((i for i in later if i.mnemonic == 'bl'), None)
        if log_call is None:
            continue
        args = [i for i in later if i.address < log_call.address and
                i.mnemonic == 'mov' and i.op_str.startswith('w2, ')]
        record = {'string_rva': hex(string), 'reference_rva': hex(pc),
                  'log_call_rva': hex(log_call.address), 'text': strings[string],
                  'evidence': image.evidence(pc - 8, log_call.address + 4)}
        logs.append(record)
        if not args:
            continue
        mode = args[-1].op_str.split(', ')[1]
        if mode == '#2':
            record['observation'] = 'Log argument is constant 2; this alone does not prove fixed control flow.'
            continue
        if not re.fullmatch(r'w\d+', mode):
            continue
        # Require the same register to select the AVB path after logging.
        dispatch = next((i for i in image.span(log_call.address + 4, log_call.address + 100)
                         if i.mnemonic == 'cmp' and i.op_str == mode + ', #2'), None)
        if dispatch is None:
            continue
        tail = image.span(dispatch.address, dispatch.address + 20)
        if (len(tail) != 5 or tail[1].mnemonic != 'b.eq' or
                tail[2].mnemonic != 'cmp' or tail[2].op_str != mode + ', #1' or
                tail[3].mnemonic != 'b.eq' or tail[4].mnemonic != 'cbnz' or
                not tail[4].op_str.startswith(mode + ', ')):
            continue
        transfer = [i for i in image.span(max(0, pc - 0x180), pc)
                    if i.mnemonic == 'mov' and i.op_str == mode + ', w0']
        if not transfer:
            continue
        mov = transfer[-1]
        previous = image.code.get(mov.address - 4)
        if previous is None or previous.mnemonic != 'bl':
            continue
        # Until the log argument is copied, ensure the mode register isn't overwritten.
        aliases = {mode, 'x' + mode[1:]}
        overwritten = False
        for i in image.span(mov.address + 4, args[-1].address):
            _, written = i.regs_access()
            if any(i.reg_name(r) in aliases for r in written):
                overwritten = True
        if overwritten or int(mode[1:]) < 19:
            continue
        result = selector(image, target(previous))
        if result:
            result.update({'mode_register': mode, 'mode_call_rva': hex(previous.address),
                           'dispatch_rva': hex(dispatch.address),
                           'usage_evidence': image.evidence(previous.address, dispatch.address + 24)})
            findings.append(result)
    detected = any(r['kind'] == 'SELECT_0_OR_2' for r in findings)
    result = {'tool_version': '1.4', 'input_name': Path(path).name, 'sha256': image.sha256,
              'pe_sha256': hashlib.sha256(image.pe).hexdigest(), 'image_base': hex(image.base),
              'result': detected, 'avb_0_or_2_detected': detected,
              'findings': findings, 'log_sites': logs,
              'scope': 'Static bootloader AVB mode selection; not vbmeta header version, runtime mode, or a boot/security bypass test.',
              'limitations': 'false means the supported 0/2 selection pattern was not detected; it does not prove absence or fixed mode 2. Missing logs, inlining, obfuscation, or changed register allocation may prevent detection. No firmware modifications.'}
    return result, image


def reproduction(result):
    """Generate a model only of the detected conversion and dispatch instructions."""
    if not result['result']:
        return ('"""No supported 0/2 selection pattern was detected in this input.\n'
                'A reproduction cannot be generated; fixed mode 2 is not assumed.\n"""\n'
                'if __name__ == "__main__":\n'
                '    raise SystemExit("Unavailable: no supported 0/2 selection pattern detected.")\n')
    finding = next(f for f in result['findings'] if f['kind'] == 'SELECT_0_OR_2')
    header = ('"""Executable model of a detected AVB mode selector.\n'
              'Only the low-byte test, conversion to 0/2, and mode dispatch are reproduced.\n'
              'The condition result is supplied by the caller, not read from a device.\n'
              'Partition lookup, logging gates, stack guards, AVB verification, and boot\n'
              'execution are NOT emulated. Path names below are descriptive placeholders.\n'
              'This model does not determine the actual runtime mode.\n"""\n'
              '# Source SHA256: ' + result['sha256'] + '\n'
              '# Selector RVA: ' + finding['selector_rva'] + '\n'
              '# Condition function RVA: ' + finding['condition_function_rva'] + '\n'
              '# Dispatch RVA: ' + finding['dispatch_rva'] + '\n\n')
    return header + '''def get_avb_mode(condition_result):
    # TST W0, #0xff; CSET W8, NE; LSL W0, W8, #1
    return 2 if (condition_result & 0xFF) != 0 else 0


def dispatch_mode(mode):
    # Comparisons use a 32-bit W register.
    mode &= 0xFFFFFFFF
    if mode == 2:
        return "MODE_2_PATH"
    if mode == 1:
        return "MODE_1_PATH"
    if mode != 0:
        return "UNSUPPORTED_MODE_PATH"
    return "MODE_0_PATH"


def simulate(condition_result):
    mode = get_avb_mode(condition_result)
    # The original firmware prints this only when its logging gates allow it.
    print(f"AVB version {mode}")
    print(f"Selected path: {dispatch_mode(mode)}")
    return mode


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("condition_result", nargs="?", type=lambda value: int(value, 0),
                        help="Simulated return value of the condition function, e.g. 0 or 1")
    args = parser.parse_args()
    if args.condition_result is None:
        for value in (0, 1):
            print(f"Condition result: {value}")
            simulate(value)
    else:
        simulate(args.condition_result)
'''


def render(result):
    lines = ['Result: ' + str(result['result']).lower(),
             'Meaning: 0/2 selection pattern detected' if result['result'] else
             'Meaning:',
             '', 'Input: ' + result['input_name'],
             '', '--- Analysis details and evidence ---', 'SHA256: ' + result['sha256'],
             'PE image base: ' + result['image_base'], 'Addresses below are PE RVAs.']
    for item in result['findings']:
        lines.append('')
        for key, value in item.items():
            if key.endswith('evidence'):
                lines.extend(value)
            else:
                lines.append('%s: %s' % (key, value))
    for item in result['log_sites']:
        lines.extend(['', 'AVB log reference: ' + item['reference_rva']])
        if 'observation' in item:
            lines.append(item['observation'])
        lines.extend(item['evidence'])
    if result['result']:
        lines.extend(['', '--- Python reproduction (partial model) ---', reproduction(result)])
    lines.extend(['', result['scope'], result['limitations']])
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('abl', type=Path, help='ABL ELF or extracted ARM64 LinuxLoader PE')
    parser.add_argument('--out', type=Path, help='Output directory for reports and avb_mode_reproduction.py')
    parser.add_argument('--export-pe', action='store_true', help='Save extracted LinuxLoader.pe (requires --out)')
    args = parser.parse_args()
    if args.export_pe and not args.out:
        parser.error('--export-pe requires --out')
    try:
        result, image = analyze(args.abl)
        report = render(result)
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / 'analysis.txt').write_text(report, encoding='utf-8')
            (args.out / 'analysis.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            (args.out / 'avb_mode_reproduction.py').write_text(reproduction(result), encoding='utf-8')
            if args.export_pe:
                (args.out / 'LinuxLoader.pe').write_bytes(image.pe)
        print(report)
        return 0
    except (OSError, ValueError, struct.error, IndexError) as exc:
        print('ERROR: %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
