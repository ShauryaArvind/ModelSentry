import os
import json
import struct
import zipfile
import pickletools
import hashlib

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
    'multiprocessing', 'threading',
    # Builtins and execution
    'builtins.eval', 'builtins.exec', 'builtins.compile', 'builtins.__import__', 
    'builtins.open', 'builtins.input', 'builtins.getattr', 'builtins.setattr',
    '__builtin__.eval', '__builtin__.exec', '__builtin__.compile', '__builtin__.__import__',
    '__builtin__.open', '__builtin__.input', '__builtin__.getattr', '__builtin__.setattr',
    'eval', 'exec', 'compile', '__import__', 'getattr', 'setattr'
}

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

def scan_file(filepath, custom_blocklist=None, custom_allowlist=None):
    """
    Routes the file to the correct scanner layer and returns a verdict dictionary.
    """
    sha256_hash = calculate_sha256(filepath)
    if not os.path.exists(filepath):
        return {
            "filepath": filepath,
            "sha256": "N/A",
            "file_type": "none",
            "verdict": "SUSPICIOUS",
            "reasons": ["File not found"],
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
            "reasons": [f"Cannot read file: {str(e)}"],
            "details": {}
        }
        
    file_type = "unknown"
    if magic.startswith(b'\x89HDF\r\n\x1a\n'):
        file_type = "hdf5"
    elif magic.startswith(b'PK\x03\x04'):
        file_type = "pytorch_zip"
    elif is_safetensors(filepath):
        file_type = "safetensors"
    else:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ('.pkl', '.pickle', '.pt', '.pth', '.bin', '.joblib'):
            file_type = "pickle"
            
    if file_type == "hdf5":
        lambdas = inspect_h5_file(filepath)
        if lambdas:
            return {
                "filepath": filepath,
                "sha256": sha256_hash,
                "file_type": "hdf5",
                "verdict": "MALICIOUS",
                "reasons": [f"Contains {len(lambdas)} Keras Lambda layer(s) which can execute arbitrary Python code on load"],
                "details": {"lambda_layers": lambdas}
            }
        else:
            return {
                "filepath": filepath,
                "sha256": sha256_hash,
                "file_type": "hdf5",
                "verdict": "SAFE",
                "reasons": ["No Keras Lambda layers detected"],
                "details": {}
            }
            
    elif file_type == "safetensors":
        verdict, reason, header = validate_safetensors(filepath)
        return {
            "filepath": filepath,
            "sha256": sha256_hash,
            "file_type": "safetensors",
            "verdict": verdict,
            "reasons": [reason],
            "details": {"header_metadata": header}
        }
        
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
                return {
                    "filepath": filepath,
                    "sha256": sha256_hash,
                    "file_type": "pytorch_zip",
                    "verdict": "SUSPICIOUS",
                    "reasons": ["Failed to extract or parse any pickle calls from the PyTorch zip archive"],
                    "details": {}
                }
            else:
                return {
                    "filepath": filepath,
                    "sha256": sha256_hash,
                    "file_type": "pytorch_zip",
                    "verdict": "SAFE",
                    "reasons": ["Zip archive contains no pickle files"],
                    "details": {}
                }
        verdict, reasons = check_rules(calls, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist)
        return {
            "filepath": filepath,
            "sha256": sha256_hash,
            "file_type": "pytorch_zip",
            "verdict": verdict,
            "reasons": reasons if reasons else ["No suspicious or blocked calls detected"],
            "details": {"extracted_calls": calls}
        }
        
    elif file_type == "pickle" or file_type == "unknown":
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            calls = extract_pickle_calls_from_bytes(content)
            
            if not calls and file_type == "unknown":
                return {
                    "filepath": filepath,
                    "sha256": sha256_hash,
                    "file_type": "unknown",
                    "verdict": "SUSPICIOUS",
                    "reasons": ["Unsupported or unrecognized file format"],
                    "details": {}
                }
                
            verdict, reasons = check_rules(calls, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist)
            return {
                "filepath": filepath,
                "sha256": sha256_hash,
                "file_type": "pickle",
                "verdict": verdict,
                "reasons": reasons if reasons else ["No suspicious or blocked calls detected"],
                "details": {"extracted_calls": calls}
            }
            return {
                "filepath": filepath,
                "sha256": sha256_hash,
                "file_type": "pickle",
                "verdict": verdict,
                "reasons": reasons if reasons else ["No suspicious or blocked calls detected"],
                "details": {"extracted_calls": calls}
            }
        except Exception as e:
            return {
                "filepath": filepath,
                "sha256": sha256_hash,
                "file_type": "unknown",
                "verdict": "SUSPICIOUS",
                "reasons": [f"Unrecognized file format or failed to read/parse: {str(e)}"],
                "details": {}
            }
