# 🛡️ ModelSentry — Static Malware Scanner for AI Model Artifacts

**ModelSentry** is a lightweight, zero-execution security scanner designed to inspect Machine Learning model files for arbitrary code execution vectors and embedded malware payloads. 

It statically analyzes `.pkl` (Pickle), `.pt`/`.pth` (PyTorch weights), `.h5` (Keras/HDF5), and `.safetensors` files **without ever executing or loading them into memory**.

---

## 1. The Security Problem

Machine learning model files are often treated as simple data assets, but popular formats can execute arbitrary code on the user's system the moment they are loaded:

*   **Pickle-based formats (`.pkl`, `.pt`, `.pth`)**: PyTorch's default save mechanism uses Python's standard `pickle` library. Attackers can embed `GLOBAL` or `STACK_GLOBAL` opcodes coupled with a `REDUCE` instruction in the bytecode. Upon loading via `torch.load()` or `pickle.load()`, the model will automatically invoke importable Python functions like `os.system` or `subprocess.Popen` without user consent.
*   **HDF5 formats (`.h5`)**: Keras models saved in the HDF5 format can contain serialized custom `Lambda` layers. These store raw serialized Python bytecode inside the file's HDF5 metadata, executing it upon calling `load_model()`.
*   **Safetensors (`.safetensors`)**: Designed to be a safe, data-only format, safetensors itself does not execute code. However, attackers can append malicious binary payloads to the end of a valid safetensors file (outside of the declared tensor offsets) to hide executables or payloads in a supply chain attack.

ModelSentry addresses these attack vectors by scanning the model structures purely through static disassembling and header verification.

---

## 2. Core Architecture & Features

ModelSentry is structured into multiple validation layers:

1.  **File Type Sniffer**: Detects the model format using magic bytes (HDF5 magic, ZIP headers for modern PyTorch archives, Safetensors header length) or file extensions.
2.  **Pickle Opcode Emulator**: Uses `pickletools` to disassemble raw pickle byte streams or pickle segments stored inside PyTorch zip archives (e.g. `archive/data.pkl`). It simulates the pickle VM stack to dynamically resolve both `GLOBAL` and `STACK_GLOBAL` (Protocol 4+) opcodes to identify all referenced modules/functions.
3.  **HDF5 Structure Inspector**: Opens `.h5` files in read-only mode using `h5py` and extracts the model's Keras layer configuration metadata. It recursively inspects the JSON definition to look for the presence of dangerous `"class_name": "Lambda"` layer structures.
4.  **Safetensors Header Validator**: Reads the 8-byte header size prefix, validates the JSON header size boundary (< 100MB), and ensures that the sum of declared tensor offsets matches the actual file size. This reliably catches files containing appended payloads/executables.
5.  **Rule Engine & Verdict Scorer**: Compares all resolved references against a strict blocklist (e.g., `os`, `subprocess`, `sys`, `socket`, `ctypes`, `eval`, `exec`) and an allowlist of standard ML libraries (`torch`, `numpy`, `collections`, etc.).
    *   **SAFE**: The file only contains references within the allowlist and matches standard layouts.
    *   **SUSPICIOUS**: The file contains unverified custom modules or minor deviations (e.g. appended payloads in Safetensors).
    *   **MALICIOUS**: The file contains explicit blocklisted calls or dangerous executable Keras Lambda layers.

---

## 3. Installation

Clone the repository and install the minimal dependencies:

```bash
git clone https://github.com/ShauryaArvind/ModelSentry.git
cd ModelSentry

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate

# Install dependencies
pip install h5py rich pytest safetensors
```

---

## 4. Usage

### Scanning a Local File
To scan a single model weights file:
```bash
python modelsentry.py scan SAMPLES/malicious_hdf5.h5
```

### Scanning a Directory (with Recursive Option)
To scan a downloaded model repository folder:
```bash
python modelsentry.py scan SAMPLES/ --recursive
```

### Outputting JSON for CI/CD Pipelines
Integrate ModelSentry into automated security workflows by outputting machine-readable JSON:
```bash
python modelsentry.py scan SAMPLES/ --recursive --json
```

### Scanning a Remote URL
You can perform a pre-download safety scan directly from a Hugging Face hub or public URL:
```bash
python modelsentry.py scan-url https://example.com/path/to/model.pt
```

---

## 5. Directory Structure

```
ModelSentry/
├── modelsentry.py      # CLI Entrypoint
├── scanner.py          # Main Scanner and Rule Engine
├── test_scanner.py     # Automated Pytest Suite
├── generate_samples.py # Script to create mock models for testing
├── SAMPLES/            # Tiny generated benign & malicious model samples
└── README.md           # Documentation
```

---

## 6. Verification & Testing

Verify that all scanning layers are operating correctly by running the test suite:

```bash
pytest test_scanner.py -v
```

---

## 7. License

This project is licensed under the MIT License.
