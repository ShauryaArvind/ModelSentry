# 🛡️ ModelSentry — Static Malware & Payload Scanner for AI Model Artifacts

**ModelSentry** is a lightweight, zero-execution security scanner designed to inspect Machine Learning model files for arbitrary code execution vectors, embedded malware payloads, and path traversal vulnerabilities.

It statically analyzes `.pkl` (Pickle), `.pt`/`.pth` (PyTorch weights), `.h5` (Keras/HDF5), `.safetensors`, `.gguf`/`.ggml` (llama.cpp format), `.onnx` (Open Neural Network Exchange), and `.npy`/`.npz` (NumPy binary arrays) **without ever executing or loading them into memory**.

---

## 1. The Security Problem

Machine learning model files are often treated as simple data assets, but popular formats can execute arbitrary code or exfiltrate system data the moment they are loaded:

*   **Pickle-based formats (`.pkl`, `.pt`, `.pth`)**: PyTorch's default save mechanism uses Python's standard `pickle` library. Attackers embed `GLOBAL` or `STACK_GLOBAL` opcodes coupled with a `REDUCE` instruction in the bytecode. Upon loading via `torch.load()` or `pickle.load()`, the model automatically invokes importable Python functions like `os.system` or `subprocess.Popen`.
*   **HDF5 formats (`.h5`)**: Keras models saved in HDF5 format can contain serialized custom `Lambda` layers. These store raw serialized Python bytecode inside the file's HDF5 metadata, executing it upon calling `load_model()`.
*   **Safetensors (`.safetensors`)**: Safetensors is designed to be a safe, data-only format. However, attackers can append malicious binary payloads outside the declared tensor byte offsets to hide executables in a supply chain attack.
*   **ONNX models (`.onnx`)**: Malicious ONNX models can contain `external_data` references specifying path traversal relative paths (`../../etc/passwd` or system paths) or embed malicious script commands within operator metadata.
*   **GGUF models (`.gguf`, `.ggml`)**: llama.cpp GGUF files contain binary key-value metadata headers and tensor offset maps that can be manipulated to hide secondary payloads or exploit parser overflow vulnerabilities.
*   **NumPy arrays (`.npy`, `.npz`)**: Arrays containing Python object types (`OBJECT` / `descr: |O`) trigger `pickle` execution upon loading if `allow_pickle=True`.

ModelSentry addresses these attack vectors by scanning model structures purely through static disassembling, structural validation, entropy analysis, and pattern matching.

---

## 2. Core Architecture & Features

ModelSentry is structured into multiple validation layers:

1.  **File Type Sniffer**: Detects model format using magic bytes (`GGUF`, HDF5 magic, `\x93NUMPY`, ZIP headers for modern PyTorch archives, Safetensors header length) or file extensions.
2.  **Pickle Opcode Emulator**: Uses `pickletools` to disassemble raw pickle byte streams or pickle segments stored inside PyTorch zip archives (e.g. `archive/data.pkl`). It simulates the pickle VM stack to dynamically resolve both `GLOBAL` and `STACK_GLOBAL` (Protocol 4+) opcodes to identify all referenced modules/functions.
3.  **HDF5 Structure Inspector**: Opens `.h5` files in read-only mode using `h5py` and extracts model configuration metadata. It recursively inspects the JSON definition for dangerous `"class_name": "Lambda"` layer structures.
4.  **Safetensors Header Validator**: Reads the 8-byte header size prefix, validates the JSON header size boundary (< 100MB), and ensures that declared tensor offsets match the actual file size to catch appended payload data.
5.  **GGUF & GGML Inspector**: Parses GGUF binary headers (magic `GGUF`/`0x46554747`), checks key-value metadata for malicious payload URLs, and verifies tensor boundaries.
6.  **ONNX Graph & Metadata Scanner**: Statically inspects ONNX model protobuf files to detect `external_data` directory escape attempts (`..`) and custom operator domain vulnerabilities.
7.  **NumPy / NPZ Object Scanner**: Inspects `.npy` and `.npz` headers for serialized Python object types and pickle opcodes.
8.  **Entropy & Payload Detector**: Calculates Shannon entropy across file windows to detect encrypted/compressed shellcode, and checks raw byte streams for embedded executable signatures (PE `MZ`, ELF `\x7fELF`, Mach-O).
9.  **Rule & Risk Scoring Engine**: Evaluates findings against custom or built-in blocklists/allowlists, assigns a numerical **Risk Score (0.0 to 10.0)**, and categorizes findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `SAFE`).

---

## 3. Installation

Clone the repository and install the minimal dependencies:

```bash
git clone https://github.com/ShauryaArvind/ModelSentry.git
cd ModelSentry

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate

# Install package or dependencies
pip install -e .
```

---

## 4. Usage

### Scanning a Local File
To scan a single model weights file:
```bash
modelsentry scan SAMPLES/malicious_hdf5.h5
```

### Scanning a Directory (Multithreaded & Recursive)
To scan a downloaded model repository folder using multi-core parallel worker threads:
```bash
modelsentry scan SAMPLES/ --recursive --threads 8
```

### Exporting SARIF v2.1.0 Reports for GitHub Security
Generate OASIS SARIF v2.1.0 reports for native GitHub Code Scanning integration:
```bash
modelsentry scan SAMPLES/ --recursive --sarif results.sarif
```

### Outputting JSON for CI/CD Pipelines
Integrate ModelSentry into automated security workflows:
```bash
modelsentry scan SAMPLES/ --recursive --json
```

### Exporting Interactive HTML & Markdown Audit Reports
Generate standalone security audit reports:
```bash
modelsentry scan SAMPLES/ --recursive --export-report audit.html
modelsentry scan SAMPLES/ --recursive --export-report audit.md
```

### Custom Blocklist, Allowlist & Ignore Suppression (`.modelsentryignore`)
Supply custom rules via text/JSON files, or suppress expected findings using `.modelsentryignore`:
```bash
# Custom blocklist/allowlist
modelsentry scan SAMPLES/ --blocklist custom_blocklist.txt --allowlist custom_allowlist.txt

# Suppress false positives or expected references via ignore file
modelsentry scan SAMPLES/ --ignore-file .modelsentryignore
```

### Scanning Remote Hugging Face Repositories (`scan-hf`)
Inspect all model weight artifacts inside a remote Hugging Face model repository before downloading:
```bash
modelsentry scan-hf gpt2
modelsentry scan-hf meta-llama/Llama-2-7b --revision main --export-report hf_audit.html
```

### Installing Git Pre-Commit Hook (`init-hook`)
Prevent committing malicious or unsafe model artifacts into your repository:
```bash
modelsentry init-hook
```

### Scanning Remote URLs & Batch URL Lists
Perform pre-download safety checks for single remote models or batch lists of model URLs:
```bash
# Single URL
modelsentry scan-url https://example.com/path/to/model.pt

# Batch list of URLs from a text file (one URL per line)
modelsentry scan-urls url_list.txt --export-report batch_audit.html
```

---

## 5. Configuration File (`.modelsentryrc` / `modelsentry.json`)

You can create a `.modelsentryrc` or `modelsentry.json` file in your project root to set persistent scanner defaults:

```json
{
  "threads": 8,
  "max_size_mb": 500,
  "min_severity": "MEDIUM",
  "blocklist": "custom_blocklist.txt",
  "allowlist": "custom_allowlist.txt",
  "ignore_file": ".modelsentryignore"
}
```

---

## 6. Directory Structure

```
ModelSentry/
├── modelsentry.py              # CLI Entrypoint & Reporting Engine
├── scanner.py                  # Static Scanners & Heuristic Engine
├── test_scanner.py             # Automated Pytest Suite
├── generate_samples.py         # Test model generator
├── pyproject.toml              # Python Package Setup
├── .github/workflows/          # GitHub Actions CI Workflow
│   └── modelsentry.yml
├── SAMPLES/                    # Generated benign & malicious test models
└── README.md                   # Documentation
```

---

## 7. Verification & Testing

Verify all scanning layers by running the automated pytest suite:

```bash
pytest test_scanner.py -v
```

---

## 8. License

This project is licensed under the MIT License.
