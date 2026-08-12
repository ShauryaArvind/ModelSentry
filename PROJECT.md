# 🛡️ PROJECT.md: ModelSentry — Malicious ML Model File Scanner
 
**Project Name:** ModelSentry (Static Malware Scanner for AI Model Artifacts)
**Category:** AI Supply Chain Security / Static Analysis
**Runs on:** CPU only, <500MB RAM during scans — fine on 8GB RAM
**Goal:** A CLI tool that inspects `.pkl`, `.pt`, `.h5`, and `.safetensors` model files for embedded malicious code **without ever executing them**, and outputs a SAFE / SUSPICIOUS / MALICIOUS verdict with reasons.
 
---
 
## 1. PROBLEM STATEMENT
 
Model files are treated as "just data" by most users, but several common formats can execute arbitrary code the moment they're loaded:
 
- **Pickle-based formats** (`.pkl`, and PyTorch's `.pt`/`.pth` which use pickle internally) can embed a `REDUCE` opcode that calls any importable Python function — including `os.system`, `subprocess.Popen`, or `eval` — automatically on `pickle.load()`.
- **Keras `.h5` files** can contain `Lambda` layers, which store a serialized Python function that executes on model load.
- **`.safetensors`** was specifically designed to avoid this class of vulnerability (no code execution by spec), but malformed headers or misuse can still be worth validating.
This is a real, actively exploited vector — malicious models have been found on public hubs disguised as legitimate fine-tunes. Almost no polished, general-purpose scanner exists for this outside of a couple of enterprise products (e.g. Protect AI's ModelScan) — which makes a clean open-source version a strong, niche portfolio piece.
 
**Design principle to hold onto throughout:** the scanner must **never call `pickle.load()`, `torch.load()`, or `keras.models.load_model()`** on an untrusted file. Everything is done via static parsing/disassembly. This constraint is the entire security value of the tool — don't compromise on it for convenience.
 
---
 
## 2. ARCHITECTURE
 
- **Layer 1: File Type Detector** — sniffs magic bytes / extension to route the file to the correct parser (pickle-family, HDF5, or safetensors).
- **Layer 2: Pickle Opcode Disassembler** — uses Python's built-in `pickletools` module to statically read pickle bytecode and extract every `GLOBAL`/`STACK_GLOBAL` reference (these show which modules/functions the file could call).
- **Layer 3: HDF5 Layer Inspector** — reads `.h5` file structure (via `h5py`, read-only) to find `Lambda` layers or other custom-code-bearing layer configs.
- **Layer 4: Safetensors Header Validator** — parses the JSON header of `.safetensors` files and checks for malformed or oversized metadata.
- **Layer 5: Rule Engine + Verdict Scorer** — matches extracted references against a maintained blocklist (`os`, `subprocess`, `sys`, `socket`, `eval`, `exec`, `__builtin__.eval`, etc.) and produces a severity score and verdict.
- **Layer 6: CLI + Report Output** — `python modelsentry.py scan <file>` prints a human-readable verdict; `--json` flag outputs machine-readable results for CI pipelines.
---
 
## 3. PHASE-WISE EXECUTION ROADMAP
 
### PHASE 1: Foundation — Pickle Opcode Reader (the core engine)
 
**Goal:** Prove you can read a pickle file's contents without executing it.
 
Steps to execute yourself, in order:
 
1. Set up a Python virtual environment and confirm `pickletools` is available (it's stdlib — no install needed).
2. Create two test files: one totally benign pickle (e.g. `pickle.dump({"weights": [1,2,3]}, ...)`), and one deliberately malicious pickle you build yourself for testing purposes only, using `__reduce__` to call something harmless like `print("would be malicious")` instead of anything actually destructive. Keep this test file local, never share it as a working exploit.
3. Write a script that runs `pickletools.dis()` on a file path and captures the output as text instead of just printing it, so you can parse it programmatically.
4. Manually inspect the disassembly output for both test files side by side. Identify exactly which opcode lines differ — you're looking for `GLOBAL` or `STACK_GLOBAL` opcodes referencing modules outside of typical ML libraries (numpy, torch, collections) in the malicious file.
5. Write a parser function that extracts every `GLOBAL`/`STACK_GLOBAL` opcode's target (module + function name) into a list, from the disassembly text.
6. Test the parser against both files and confirm it correctly lists `builtins.print` (or whatever function you used) as a referenced call in the malicious file, and nothing suspicious in the benign one.
**Checkpoint:** you should now have a function `extract_pickle_calls(filepath) -> list[str]` that works without ever loading the actual pickle object.
 
---
 
### PHASE 2: Rule Engine & Verdict Logic
 
**Goal:** Turn the raw list of referenced calls into a meaningful SAFE/SUSPICIOUS/MALICIOUS verdict.
 
Steps to execute yourself, in order:
 
1. Research and write down a blocklist of Python modules/functions that have no legitimate reason to appear in a model weights file: `os`, `subprocess`, `sys`, `socket`, `shutil`, `eval`, `exec`, `compile`, `__import__`, `builtins.eval`, `pty`, `ctypes`. Also research and note an "allowlist" of expected references for legitimate ML files: `numpy.core.multiarray`, `torch._utils`, `collections.OrderedDict`, `numpy.dtype`, etc.
2. Design a scoring system: e.g. any blocklist hit = MALICIOUS (high confidence), any reference not in the allowlist and not in the blocklist = SUSPICIOUS (unknown, flag for review), everything matching the allowlist = SAFE.
3. Write the verdict function that takes the list from Phase 1 and returns a verdict + a plain-English reason (e.g. "References os.system — this can execute arbitrary shell commands on load").
4. Test against your two sample files from Phase 1 and confirm correct verdicts.
5. Build 3–5 more synthetic test pickles covering edge cases: a file with an allowlisted-only reference, a file with an unknown-but-not-blocklisted reference, a file with multiple blocklist hits. Confirm your scorer handles all of them sensibly.
6. Write this test suite as an actual automated test file (`pytest`) rather than manual runs — this also strengthens the "engineering rigor" story for your resume writeup.
**Checkpoint:** a tested, deterministic function `get_verdict(calls: list[str]) -> (verdict, reasons)`.
 
---
 
### PHASE 3: Multi-Format Support (HDF5 + Safetensors)
 
**Goal:** Extend beyond pickle so the tool covers the three most common formats people actually download.
 
Steps to execute yourself, in order:
 
1. Install `h5py` and create a benign `.h5` test file (any small Keras `Sequential` model saved with `model.save()`).
2. Create a second `.h5` test file that includes a `Lambda` layer with a small serialized function, to act as your malicious test case.
3. Write a function that opens the `.h5` file in read-only mode and walks its layer config (stored as JSON inside the file's attributes) — do **not** call `keras.models.load_model()`. Look specifically for `"class_name": "Lambda"` entries.
4. Confirm your function correctly flags the Lambda-containing file and passes the clean one.
5. Download or construct a small `.safetensors` file (Hugging Face has plenty of tiny examples, or you can create one with the `safetensors` library from a small tensor).
6. Write a function that reads just the JSON header (first 8 bytes give header length, then parse that many bytes as JSON) and validates it's well-formed, checking for suspicious oversized metadata fields or non-standard keys.
7. Add a file-type detection layer at the top of your tool: read magic bytes / extension, route to the right parser (pickle family vs HDF5 vs safetensors).
**Checkpoint:** your tool can now correctly classify a file of any of the three types.
 
---
 
### PHASE 4: CLI, Reporting, and Portfolio Polish
 
**Goal:** Package this into something a recruiter or judge can actually run and understand in under a minute.
 
Steps to execute yourself, in order:
 
1. Build a proper CLI using `argparse` or `click`: `python modelsentry.py scan <path>` for single files, `python modelsentry.py scan <directory> --recursive` for scanning a whole downloaded model repo folder.
2. Add a `--json` output mode that prints a structured report (filename, verdict, matched rules, timestamp) — this signals "CI/CD-ready tool," which reads well on a resume.
3. Add color-coded terminal output (green/yellow/red) for the three verdicts using a lightweight library like `rich` — small effort, big visual impact for a demo video or screenshot.
4. Write a `SAMPLES/` folder with your synthetic benign and malicious test files from Phases 1–3, clearly labeled, so anyone cloning your repo can immediately run and see it work — this is what makes a security tool credible on GitHub instead of just a claim.
5. Write a clean `README.md`: problem statement, how it works (mention specifically that it uses static analysis and never executes untrusted input — this is your strongest technical talking point), install/usage instructions, and a screenshot or terminal recording (use `asciinema` or a simple screen recording) of it catching a malicious file.
6. Optional stretch goal if you have time before the deadline: add a `--scan-url` mode that downloads a model file from a given Hugging Face URL into a temp file and scans it before deleting it, to simulate a "pre-download safety check" workflow. This is a strong demo moment.
7. Push to GitHub with a clear repo name (`modelsentry` or similar), MIT license, and topics tagged (`security`, `mlsecurity`, `static-analysis`, `pickle`) so it's discoverable and looks maintained.
**Checkpoint:** a working, documented, publicly runnable tool with test samples — ready to link on your resume.
 
---
 
## 4. RESUME / DEMO FRAMING NOTES
 
- **One-line resume bullet:** *"Built a static analysis security scanner detecting arbitrary code execution vectors in ML model files (pickle, HDF5, safetensors), addressing a real AI supply-chain attack vector with zero runtime execution risk."*
- **If asked about it in an interview:** be ready to explain the pickle `REDUCE`/`GLOBAL` opcode mechanism in your own words — this is the part that separates "I used a library" from "I understand the vulnerability class." You built the disassembly-based detection yourself in Phase 1, so this should come naturally.
- **Demo moment that lands well:** side-by-side terminal — scan the benign file (green, SAFE), then scan your malicious test file (red, MALICIOUS, with the exact reason shown). Takes 15 seconds and is very visual for a judge or recruiter.
