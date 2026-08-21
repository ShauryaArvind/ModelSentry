import os
import re
import json
import math
import struct
import zipfile
import pickletools
import hashlib

import fnmatch

def calculate_sha256(filepath):
    """Calculates the SHA-256 hex digest of a file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "N/A"

# Rule-based detection settings
BLOCKLIST = {
    # OS / Process control
    'os', 'subprocess', 'sys', 'socket', 'shutil', 'pty', 'ctypes', 
    'webbrowser', 'tempfile', 'requests', 'urllib', 'posix', 'nt', 
    'platform', 'runpy', 'importlib', 'code', 'pdb', 'commands', 
    'multiprocessing', 'threading', 'asyncio', 'winreg', 'ftplib',
    'poplib', 'smtplib', 'http.client', 'pickle', 'marshal',
    # Builtins and execution
    'builtins.eval', 'builtins.exec', 'builtins.compile', 'builtins.__import__', 
    'builtins.open', 'builtins.input', 'builtins.getattr', 'builtins.setattr',
    '__builtin__.eval', '__builtin__.exec', '__builtin__.compile', '__builtin__.__import__',
    '__builtin__.open', '__builtin__.input', '__builtin__.getattr', '__builtin__.setattr',
    'eval', 'exec', 'compile', '__import__', 'getattr', 'setattr'
}

DANGEROUS_PATTERNS = [
    (re.compile(b'(?:/bin/sh|/bin/bash|powershell\\.exe|cmd\\.exe)\\s+-[ic]'), "Embedded interactive shell execution command"),
    (re.compile(b'AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|PRIVATE_KEY'), "Potential credential / API key harvesting reference"),
    (re.compile(b'socket\\.(?:AF_INET|SOCK_STREAM|socket)'), "Raw network socket creation reference"),
    (re.compile(b'http[s]?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}'), "Hardcoded IP address endpoint reference"),
]

def load_custom_rules_file(filepath):
    """
    Loads custom rules (blocklist or allowlist entries) from a text or JSON file.
    """
    entries = set()
    if not filepath or not os.path.exists(filepath):
        return entries
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content.startswith('{') or content.startswith('['):
                data = json.loads(content)
                if isinstance(data, list):
                    entries.update(data)
                elif isinstance(data, dict):
                    entries.update(data.get("rules", []))
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        entries.add(line)
    except Exception:
        pass
    return entries

def load_ignore_file(filepath=None):
    """
    Loads suppression rules from a .modelsentryignore file or custom ignore file path.
    Entries can be file path patterns, SHA256 hashes, or specific rule / module substrings.
    """
    entries = set()
    paths_to_check = [filepath] if filepath else [".modelsentryignore"]
    for path in paths_to_check:
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            entries.add(line)
                break
            except Exception:
                pass
    return entries

def is_ignored(filepath, sha256_hash, reason_or_call, ignore_entries):
    """
    Checks if a specific file, hash, or finding reason matches any ignore entry.
    """
    if not ignore_entries:
        return False
    norm_path = os.path.normpath(filepath).replace('\\', '/')
    for entry in ignore_entries:
        entry_str = entry.strip()
        if not entry_str:
            continue
        entry_norm = os.path.normpath(entry_str).replace('\\', '/')
        if entry_norm == norm_path or fnmatch.fnmatch(norm_path, entry_norm) or entry_norm == sha256_hash or (sha256_hash and sha256_hash.startswith(entry_norm)):
            return True
        if reason_or_call:
            if entry_str in reason_or_call:
                return True
            if entry_str.startswith('os.') and entry_str.replace('os.', 'nt.', 1) in reason_or_call:
                return True
            if entry_str.startswith('os.') and entry_str.replace('os.', 'posix.', 1) in reason_or_call:
                return True
    return False


def is_allowlisted(ref: str, custom_allowlist=None) -> bool:
    """
    Check if a reference is known to be clean and standard for machine learning files.
    """
    if custom_allowlist and (ref in custom_allowlist or ref.split('.')[0] in custom_allowlist):
        return True

    parts = ref.split('.')
    base_module = parts[0]
    
    # Standard ML modules are safe
    if base_module in ('torch', 'numpy', 'collections', '_codecs', 'copyreg'):
        return True
        
    # Specific allowed builtins
    allowed_builtins = {
        'dict', 'list', 'set', 'tuple', 'str', 'int', 'float', 'bool', 
        'complex', 'bytes', 'bytearray', 'slice', 'frozenset', 'OrderedDict', 'defaultdict'
    }
    
    if base_module in ('builtins', '__builtin__'):
        if len(parts) > 1 and parts[1] in allowed_builtins:
            return True
            
    if ref in allowed_builtins:
        return True
        
    return False

def check_rules(calls, custom_blocklist=None, custom_allowlist=None):
    """
    Matches extracted references against the blocklist and allowlist.
    Returns: (verdict, reasons)
    """
    verdict = "SAFE"
    reasons = []
    
    active_blocklist = set(BLOCKLIST)
    if custom_blocklist:
        active_blocklist.update(custom_blocklist)
        
    malicious_calls = []
    suspicious_calls = []
    
    for call in calls:
        is_blocked = False
        for blocked in active_blocklist:
            if call == blocked or call.startswith(blocked + '.'):
                is_blocked = True
                break
                
        if is_blocked:
            malicious_calls.append(call)
        elif not is_allowlisted(call, custom_allowlist=custom_allowlist):
            suspicious_calls.append(call)
            
    if malicious_calls:
        verdict = "MALICIOUS"
        for call in malicious_calls:
            reasons.append(f"Blocked reference: '{call}' (Arbitrary code execution risk)")
            
    if suspicious_calls:
        if verdict == "SAFE":
            verdict = "SUSPICIOUS"
        for call in suspicious_calls:
            reasons.append(f"Unknown/unverified reference: '{call}'")
            
    return verdict, reasons

def extract_pickle_calls_from_bytes(pickle_bytes):
    """
    Statically reads pickle bytecode to extract all global references without executing them.
    """
    calls = []
    stack = []
    memo = {}
    
    try:
        for op, arg, pos in pickletools.genops(pickle_bytes):
            op_name = op.name
            
            # 1. Handle string/unicode pushes
            if op_name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING"):
                stack.append(arg)
            
            # 2. Push placeholders for basic data types to keep stack depth accurate
            elif op_name in ("BININT", "BININT1", "BININT2", "INT", "LONG", "FLOAT", "BINFLOAT"):
                stack.append("NUM_OBJ")
            elif op_name in ("NEWTRUE", "NEWFALSE"):
                stack.append("BOOL_OBJ")
            elif op_name == "NONE":
                stack.append("NONE_OBJ")
            elif op_name == "MARK":
                stack.append("MARK_OBJ")
            
            # 3. Handle GLOBAL opcode
            elif op_name == "GLOBAL":
                if arg:
                    parts = arg.replace('\n', ' ').split()
                    if len(parts) >= 2:
                        calls.append(f"{parts[0]}.{parts[1]}")
                    elif len(parts) == 1:
                        calls.append(parts[0])
                stack.append("GLOBAL_OBJ")
                
            # 4. Handle STACK_GLOBAL opcode (Protocol 4+)
            elif op_name == "STACK_GLOBAL":
                if len(stack) >= 2:
                    name = stack.pop()
                    module = stack.pop()
                    if isinstance(module, str) and isinstance(name, str):
                        calls.append(f"{module}.{name}")
                stack.append("GLOBAL_OBJ")
                
            # 5. Handle memoization to preserve stack references across GET/PUT
            elif op_name == "MEMOIZE":
                if stack:
                    idx = len(memo)
                    memo[idx] = stack[-1]
            elif op_name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack and arg is not None:
                    memo[arg] = stack[-1]
            elif op_name in ("GET", "BINGET", "LONG_BINGET"):
                if arg is not None and arg in memo:
                    stack.append(memo[arg])
                else:
                    stack.append("MEMO_VAL")
                    
            # 6. Handle collection builders to keep stack accurate
            elif op_name in ("TUPLE", "LIST", "DICT"):
                try:
                    while stack and stack[-1] != "MARK_OBJ":
                        stack.pop()
                    if stack and stack[-1] == "MARK_OBJ":
                        stack.pop()
                except IndexError:
                    pass
                stack.append("COLL_OBJ")
            elif op_name == "TUPLE1" and len(stack) >= 1:
                stack.pop()
                stack.append("COLL_OBJ")
            elif op_name == "TUPLE2" and len(stack) >= 2:
                stack.pop(); stack.pop()
                stack.append("COLL_OBJ")
            elif op_name == "TUPLE3" and len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()
                stack.append("COLL_OBJ")
            elif op_name in ("SETITEM", "APPEND"):
                if len(stack) >= 2:
                    stack.pop(); stack.pop()
            elif op_name in ("SETITEMS", "APPENDS"):
                try:
                    while stack and stack[-1] != "MARK_OBJ":
                        stack.pop()
                    if stack and stack[-1] == "MARK_OBJ":
                        stack.pop()
                except IndexError:
                    pass
                
    except Exception:
        # Gracefully handle corrupted opcodes
        pass
        
    return list(set(calls))

def extract_pickle_calls_from_zip(filepath):
    """
    Scans a PyTorch zip archive statically for all .pkl files and extracts globals.
    """
    calls = []
    try:
        with zipfile.ZipFile(filepath, 'r') as z:
            for name in z.namelist():
                if name.endswith('.pkl') or name.endswith('.pickle'):
                    pkl_bytes = z.read(name)
                    calls.extend(extract_pickle_calls_from_bytes(pkl_bytes))
    except Exception:
        pass
    return list(set(calls))

def inspect_h5_file(filepath):
    """
    Statically extracts Lambda layers from a Keras HDF5 file.
    """
    import h5py
    lambdas = []
    try:
        with h5py.File(filepath, 'r') as f:
            if 'model_config' in f.attrs:
                config_raw = f.attrs['model_config']
                if isinstance(config_raw, bytes):
                    config_raw = config_raw.decode('utf-8')
                config = json.loads(config_raw)
                lambdas = find_lambda_layers(config)
    except Exception:
        pass
    return lambdas

def find_lambda_layers(config):
    """
    Helper function to recursively walk Keras JSON configuration structure.
    """
    lambdas = []
    if isinstance(config, dict):
        if config.get("class_name") == "Lambda":
            lambdas.append(config)
        for val in config.values():
            lambdas.extend(find_lambda_layers(val))
    elif isinstance(config, list):
        for item in config:
            lambdas.extend(find_lambda_layers(item))
    return lambdas

def is_safetensors(filepath):
    """
    Simple check to identify if a file format matches safetensors header spec.
    """
    try:
        with open(filepath, 'rb') as f:
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                return False
            header_size = struct.unpack('<Q', header_size_bytes)[0]
            if header_size <= 0 or header_size > 100 * 1024 * 1024:
                return False
            
            f.seek(0, 2)
            file_size = f.tell()
            if header_size + 8 > file_size:
                return False
            
            f.seek(8)
            header_bytes = f.read(header_size)
            if len(header_bytes) < header_size:
                return False
                
            json.loads(header_bytes.decode('utf-8'))
            return True
    except Exception:
        return False

def validate_safetensors(filepath):
    """
    Parses and checks the header of a safetensors file for layout safety.
    """
    try:
        file_size = os.path.getsize(filepath)
        if file_size < 8:
            return "MALICIOUS", "File is too small to be a valid safetensors file", {}
            
        with open(filepath, 'rb') as f:
            header_size_bytes = f.read(8)
            header_size = struct.unpack('<Q', header_size_bytes)[0]
            
            if header_size <= 0:
                return "MALICIOUS", f"Invalid safetensors header size: {header_size}", {}
            if header_size > 100 * 1024 * 1024:
                return "MALICIOUS", f"Safetensors header size is too large ({header_size} bytes)", {}
            if header_size + 8 > file_size:
                return "MALICIOUS", f"Safetensors header size ({header_size} bytes) exceeds file size", {}
                
            header_bytes = f.read(header_size)
            if len(header_bytes) < header_size:
                return "MALICIOUS", "Truncated safetensors header", {}
                
            header = json.loads(header_bytes.decode('utf-8'))
            
            max_offset = 0
            has_tensors = False
            for k, v in header.items():
                if k == "__metadata__":
                    continue
                if isinstance(v, dict) and "data_offsets" in v:
                    offsets = v["data_offsets"]
                    if isinstance(offsets, list) and len(offsets) == 2:
                        max_offset = max(max_offset, offsets[1])
                        has_tensors = True
                        
            expected_file_size = 8 + header_size + max_offset
            
            if has_tensors:
                diff = file_size - expected_file_size
                if diff > 1024:
                    return "SUSPICIOUS", f"Safetensors file has {diff} bytes of extra appended payload data at the end", header
                elif diff < 0:
                    return "MALICIOUS", f"Safetensors file is truncated by {abs(diff)} bytes", header
            
            return "SAFE", "Safetensors header is valid and matches file size", header
            
    except json.JSONDecodeError:
        return "MALICIOUS", "Safetensors header is not valid JSON", {}
    except Exception as e:
        return "MALICIOUS", f"Failed to parse safetensors file: {str(e)}", {}

def validate_gguf(filepath):
    """
    Statically inspects GGUF / GGML model binary headers.
    GGUF structure: magic (4 bytes 'GGUF' = 0x46554747), version (uint32), tensor_count (uint64), kv_count (uint64).
    """
    try:
        file_size = os.path.getsize(filepath)
        if file_size < 24:
            return "MALICIOUS", "File too small for valid GGUF header", {}
            
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            if magic != b'GGUF':
                return "SUSPICIOUS", "Invalid GGUF magic bytes", {}
                
            version, tensor_count, kv_count = struct.unpack('<IQQ', f.read(20))
            if version not in (1, 2, 3):
                return "SUSPICIOUS", f"Unrecognized GGUF header version: {version}", {}
                
            details = {
                "version": version,
                "tensor_count": tensor_count,
                "kv_count": kv_count
            }
            
            # Check for suspicious metadata or trailing payload bytes
            if kv_count > 100000 or tensor_count > 1000000:
                return "SUSPICIOUS", "Abnormally large GGUF metadata counts", details
                
            return "SAFE", f"Valid GGUF v{version} model (tensors: {tensor_count}, metadata entries: {kv_count})", details
    except Exception as e:
        return "SUSPICIOUS", f"Failed to parse GGUF file: {str(e)}", {}

def inspect_onnx_file(filepath):
    """
    Statically inspects ONNX model files for external path traversal or custom unsafe operators.
    """
    reasons = []
    details = {}
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            
        # 1. Look for external data path traversal attempts
        if b"external_data" in content:
            if b".." in content or b"/" in content or b"\\" in content:
                reasons.append("ONNX file contains external data path reference with potential directory traversal (..) signature")
                
        # 2. Check for unsafe custom operators or script metadata
        if b"CustomOp" in content or b"custom_domain" in content:
            reasons.append("ONNX file specifies custom operator domain (requires runtime extension)")
            
        if b"system(" in content or b"eval(" in content:
            reasons.append("ONNX metadata contains executable command strings")
            
        if reasons:
            verdict = "MALICIOUS" if any("executable" in r or "traversal" in r for r in reasons) else "SUSPICIOUS"
            return verdict, reasons, details
            
        return "SAFE", ["Valid ONNX protobuf file structure"], details
    except Exception as e:
        return "SUSPICIOUS", [f"Error reading ONNX file: {str(e)}"], details

def inspect_npy_npz_file(filepath):
    """
    Statically inspects NumPy .npy and .npz model data files for embedded pickle bytecodes or object arrays.
    """
    try:
        if filepath.endswith('.npz'):
            with zipfile.ZipFile(filepath, 'r') as z:
                calls = []
                has_object_arrays = False
                for name in z.namelist():
                    if name.endswith('.npy'):
                        data = z.read(name)
                        if b"'allow_pickle': True" in data or b"|O" in data:
                            has_object_arrays = True
                        calls.extend(extract_pickle_calls_from_bytes(data))
                        
                if calls:
                    verdict, reasons = check_rules(calls)
                    return verdict, reasons, {"extracted_calls": calls}
                elif has_object_arrays:
                    return "SUSPICIOUS", ["NPZ archive contains Python object arrays requiring pickle deserialization"], {}
                return "SAFE", ["NPZ archive contains clean NumPy binary arrays"], {}
        else:
            with open(filepath, 'rb') as f:
                header = f.read(256)
                if not header.startswith(b'\x93NUMPY'):
                    return "SUSPICIOUS", "Invalid NumPy magic bytes", {}
                
                content = f.read()
                calls = extract_pickle_calls_from_bytes(header + content)
                if calls:
                    verdict, reasons = check_rules(calls)
                    return verdict, reasons, {"extracted_calls": calls}
                elif b"'allow_pickle': True" in header or b"|O" in header:
                    return "SUSPICIOUS", ["NumPy file contains Python Object arrays requiring pickle execution"], {}
                    
            return "SAFE", ["Clean NumPy binary array file"], {}
    except Exception as e:
        return "SUSPICIOUS", [f"Failed to inspect NumPy file: {str(e)}"], {}

def analyze_entropy_and_payloads(filepath):
    """
    Calculates Shannon entropy across chunks and checks raw file buffers for hidden binary payloads.
    """
    findings = []
    try:
        with open(filepath, 'rb') as f:
            content = f.read(1048576) # Inspect first 1MB buffer
            
        if not content:
            return findings
            
        # 1. Embedded binary magic byte signatures
        if b'MZ' in content[:512]:
            findings.append("Embedded Windows Portable Executable (PE / .exe / .dll) magic header detected")
        if b'\x7fELF' in content[:512]:
            findings.append("Embedded Linux Executable (ELF) magic header detected")
        if content.startswith(b'\xca\xfe\xba\xbe') or content.startswith(b'\xcf\xfa\xed\xfe'):
            findings.append("Embedded macOS Mach-O binary magic header detected")
            
        # 2. Shannon Entropy check
        byte_counts = [0] * 256
        for byte in content:
            byte_counts[byte] += 1
        
        entropy = 0.0
        length = len(content)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
                
        if entropy > 7.95 and not filepath.endswith(('.h5', '.zip', '.pt', '.pth', '.npz', '.gz')):
            findings.append(f"Unusually high byte entropy ({entropy:.2f} / 8.0), suggesting encrypted/packed shellcode payload")
            
    except Exception:
        pass
        
    return findings

def scan_dangerous_patterns(filepath):
    """
    Performs static regex matching over raw file content for dangerous commands or credentials.
    """
    findings = []
    try:
        with open(filepath, 'rb') as f:
            content = f.read(524288) # First 512KB
            for pattern, msg in DANGEROUS_PATTERNS:
                if pattern.search(content):
                    findings.append(f"Dangerous pattern detected: {msg}")
    except Exception:
        pass
    return findings

def calculate_risk_score(verdict, reasons, file_type):
    """
    Calculates a numerical risk score (0.0 to 10.0) and assigns severity level.
    """
    if verdict == "MALICIOUS":
        score = 9.5
        severity = "CRITICAL"
    elif verdict == "SUSPICIOUS":
        score = 5.5
        severity = "MEDIUM"
        if any("extra appended payload" in r or "high byte entropy" in r for r in reasons):
            score = 7.5
            severity = "HIGH"
    else:
        score = 0.0
        severity = "SAFE"
        
    return round(score, 1), severity

def scan_file(filepath, custom_blocklist=None, custom_allowlist=None, max_size_mb=None, ignore_file=None, ignore_entries=None):
    """
    Routes the file to the correct scanner layer and returns a verdict dictionary.
    """
    sha256_hash = calculate_sha256(filepath)
    active_ignores = ignore_entries if ignore_entries is not None else load_ignore_file(ignore_file)

    if active_ignores and is_ignored(filepath, sha256_hash, "", active_ignores):
        return {
            "filepath": filepath,
            "sha256": sha256_hash,
            "file_type": "ignored",
            "verdict": "SAFE",
            "risk_score": 0.0,
            "severity": "SAFE",
            "reasons": ["Suppressed by ignore rules"],
            "details": {}
        }

    if not os.path.exists(filepath):
        return {
            "filepath": filepath,
            "sha256": "N/A",
            "file_type": "none",
            "verdict": "SUSPICIOUS",
            "risk_score": 5.0,
            "severity": "MEDIUM",
            "reasons": ["File not found"],
            "details": {}
        }
        
    if max_size_mb is not None and os.path.exists(filepath):
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if file_size_mb > max_size_mb:
            return {
                "filepath": filepath,
                "sha256": sha256_hash,
                "file_type": "large_file",
                "verdict": "SUSPICIOUS",
                "risk_score": 4.0,
                "severity": "MEDIUM",
                "reasons": [f"File size ({file_size_mb:.2f} MB) exceeds maximum allowed threshold of {max_size_mb} MB"],
                "details": {}
            }
        
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(8)
    except Exception as e:
        return {
            "filepath": filepath,
            "sha256": sha256_hash,
            "file_type": "none",
            "verdict": "SUSPICIOUS",
            "risk_score": 5.0,
            "severity": "MEDIUM",
            "reasons": [f"Cannot read file: {str(e)}"],
            "details": {}
        }
        
    file_type = "unknown"
    ext = os.path.splitext(filepath)[1].lower()
    
    if magic.startswith(b'\x89HDF\r\n\x1a\n'):
        file_type = "hdf5"
    elif magic.startswith(b'PK\x03\x04') and ext in ('.pt', '.pth', '.bin', '.zip'):
        file_type = "pytorch_zip"
    elif magic.startswith(b'GGUF'):
        file_type = "gguf"
    elif magic.startswith(b'\x93NUMPY') or ext in ('.npy', '.npz'):
        file_type = "numpy"
    elif ext == '.onnx' or magic.startswith(b'\x08') or magic.startswith(b'\x0a'):
        file_type = "onnx"
    elif is_safetensors(filepath):
        file_type = "safetensors"
    elif ext in ('.pkl', '.pickle', '.pt', '.pth', '.bin', '.joblib'):
        file_type = "pickle"

    # Core Parser Execution
    reasons = []
    details = {}
    verdict = "SAFE"
    
    if file_type == "hdf5":
        lambdas = inspect_h5_file(filepath)
        if lambdas:
            verdict = "MALICIOUS"
            reasons = [f"Contains {len(lambdas)} Keras Lambda layer(s) which can execute arbitrary Python code on load"]
            details = {"lambda_layers": lambdas}
        else:
            verdict = "SAFE"
            reasons = ["No Keras Lambda layers detected"]
            
    elif file_type == "gguf":
        verdict, reason, details = validate_gguf(filepath)
        reasons = [reason]
        
    elif file_type == "onnx":
        verdict, reasons, details = inspect_onnx_file(filepath)
        
    elif file_type == "numpy":
        verdict, reasons, details = inspect_npy_npz_file(filepath)
        
    elif file_type == "safetensors":
        verdict, reason, header = validate_safetensors(filepath)
        reasons = [reason]
        details = {"header_metadata": header}
        
    elif file_type == "pytorch_zip":
        calls = extract_pickle_calls_from_zip(filepath)
        if not calls:
            has_pickles = False
            try:
                with zipfile.ZipFile(filepath, 'r') as z:
                    has_pickles = any(name.endswith('.pkl') or name.endswith('.pickle') for name in z.namelist())
            except Exception:
                pass
            if has_pickles:
                verdict = "SUSPICIOUS"
                reasons = ["Failed to extract or parse any pickle calls from the PyTorch zip archive"]
            else:
                verdict = "SAFE"
                reasons = ["Zip archive contains no pickle files"]
        else:
            verdict, rule_reasons = check_rules(calls, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist)
            reasons = rule_reasons if rule_reasons else ["No suspicious or blocked calls detected"]
            details = {"extracted_calls": calls}
            
    elif file_type == "pickle" or file_type == "unknown":
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            calls = extract_pickle_calls_from_bytes(content)
            
            if not calls and file_type == "unknown":
                verdict = "SUSPICIOUS"
                reasons = ["Unsupported or unrecognized file format"]
            else:
                verdict, rule_reasons = check_rules(calls, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist)
                reasons = rule_reasons if rule_reasons else ["No suspicious or blocked calls detected"]
                details = {"extracted_calls": calls}
        except Exception as e:
            verdict = "SUSPICIOUS"
            reasons = [f"Unrecognized file format or failed to read/parse: {str(e)}"]

    # Auxiliary Heuristic & Payload Checks
    payload_findings = analyze_entropy_and_payloads(filepath)
    if payload_findings:
        reasons.extend(payload_findings)
        if verdict == "SAFE":
            verdict = "SUSPICIOUS"
            
    pattern_findings = scan_dangerous_patterns(filepath)
    if pattern_findings:
        reasons.extend(pattern_findings)
        if verdict == "SAFE":
            verdict = "SUSPICIOUS"

    # Filter out findings matched by ignore entries
    if active_ignores and reasons:
        filtered_reasons = [r for r in reasons if not is_ignored(filepath, sha256_hash, r, active_ignores)]
        if not filtered_reasons:
            verdict = "SAFE"
            reasons = ["All security findings suppressed by ignore rules"]
        else:
            reasons = filtered_reasons

    risk_score, severity = calculate_risk_score(verdict, reasons, file_type)
    
    return {
        "filepath": filepath,
        "sha256": sha256_hash,
        "file_type": file_type,
        "verdict": verdict,
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons,
        "details": details
    }
