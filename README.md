# ABL AVB Mode Analyzer

Read-only static analysis of ARM64 ABL ELF files and extracted LinuxLoader PE images. Detects supported code patterns that select AVB mode 0 or 2. Codex, Ghidra, and ADB are not required. Input files are never modified.

## Requirements

Python 3.8 or later and Capstone 5.x:

```bat
python -m pip install "capstone>=5,<6"
```

## Usage

```bat
python avb_mode_tool.py "C:\firmware\abl.elf" --out "C:\results\avb" --export-pe
```

You can pass the same arguments to `start.cmd`. Relative paths are resolved from the current working directory.

Without `--out`, the report is printed only. With `--out`, the tool saves `analysis.txt`, `analysis.json`, and `avb_mode_reproduction.py`. Existing files with those names are overwritten. Use a separate output directory to retain earlier results. `--export-pe` also saves the extracted `LinuxLoader.pe` for Ghidra.

## Results

When a supported 0/2 selection pattern is detected:

```text
Result: true
Meaning: 0/2 selection pattern detected
```

Otherwise:

```text
Result: false
Meaning:
```

`false` means the supported pattern was not detected. It does **not** prove that the code is absent or that AVB mode is fixed at 2. Different compiler output, inlining, missing logs, or changed register allocation may prevent detection. No model-specific hash allowlist is used.

The JSON report retains boolean fields `result` and `avb_0_or_2_detected`. Detailed findings include instruction addresses and evidence.

## Python reproduction

For a detected 0/2 selector, the report includes readable Python code. The output directory also contains a standalone script that needs only Python's standard library:

```bat
python results\avb_mode_reproduction.py
python results\avb_mode_reproduction.py 0
python results\avb_mode_reproduction.py 1
```

With no argument, it demonstrates both condition results. The argument supplies the simulated return value of the firmware's condition function. The model reproduces the low-byte test, conversion to mode 0/2, and dispatch. It does not perform partition lookup or infer the condition from the connected device. Verification, boot execution, logging gates, and stack guards are not emulated. The script records source hash and relevant RVAs for reference.

For a `false` result, the script is replaced by an explicit unavailable message; it does not invent fixed-mode behavior. This also prevents a reproduction from a previous input from remaining when the same output directory is reused.

## Scope and limitations

- Detects known ARM64 instruction patterns, not every possible implementation.
- An AVB log containing a constant 2 alone is not treated as proof of fixed-mode control flow.
- Analyzes bootloader AVB mode selection, not the vbmeta header version.
- Does not establish the runtime mode, signature acceptance, bootability of modified images, or whether rollback indexes can be cleared.
- Supports ARM64 PE32+ and known ABL ELF containers with an LZMA-alone payload starting near offsets 0x1000–0x1FFF. Unsupported or ambiguous containers produce an error, not `false`.
- Reported addresses are PE RVAs. With Ghidra Image Base 0, use them directly; otherwise add the Image Base.

Exit codes: `0` = analysis completed (either true or false); `2` = execution error.

Reports contain the input file name and hashes, but not its absolute path. Do not include firmware or personal analysis results when redistributing the tool.
