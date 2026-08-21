import os
import json
import struct
import pickle
import zipfile
import pytest
import h5py
from scanner import scan_file, load_ignore_file, extract_pickle_calls_from_bytes, validate_safetensors, validate_gguf, inspect_onnx_file, calculate_risk_score
from modelsentry import export_sarif_report, load_config_file, init_pre_commit_hook, handle_hf_scan

class MockMaliciousReduce:
    def __init__(self, func, args):
        self.func = func
        self.args = args
    def __reduce__(self):
        return (self.func, self.args)

@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path

def test_benign_pickle(temp_dir):
    file_path = temp_dir / "benign.pkl"
    data = {"weights": [1.0, 2.0, 3.0]}
    with open(file_path, "wb") as f:
        pickle.dump(data, f)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SAFE"
    assert result["file_type"] == "pickle"
    assert result["risk_score"] == 0.0

def test_malicious_pickle_blocked(temp_dir):
    import os as local_os
    file_path = temp_dir / "malicious_blocked.pkl"
    malicious_obj = MockMaliciousReduce(local_os.system, ("echo 'hack'",))
    with open(file_path, "wb") as f:
        pickle.dump(malicious_obj, f)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "MALICIOUS"
    assert result["severity"] == "CRITICAL"
    assert any("Blocked reference:" in r and "system" in r for r in result["reasons"])

def test_suspicious_pickle_unknown(temp_dir):
    file_path = temp_dir / "suspicious.pkl"
    pickle_bytes = b"cmy_custom_module\nmy_function\n(I1\ntR."
    with open(file_path, "wb") as f:
        f.write(pickle_bytes)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SUSPICIOUS"
    assert any("Unknown/unverified reference: 'my_custom_module.my_function'" in r for r in result["reasons"])

def test_pytorch_zip_malicious(temp_dir):
    file_path = temp_dir / "pytorch_model.pt"
    import os as local_os
    malicious_obj = MockMaliciousReduce(local_os.system, ("echo 'hack'",))
    pickle_bytes = pickle.dumps(malicious_obj)
    
    with zipfile.ZipFile(file_path, 'w') as z:
        z.writestr("archive/data.pkl", pickle_bytes)
        z.writestr("archive/version", b"3")
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "MALICIOUS"
    assert result["file_type"] == "pytorch_zip"
    assert any("Blocked reference:" in r and "system" in r for r in result["reasons"])

def test_benign_hdf5(temp_dir):
    file_path = temp_dir / "benign.h5"
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {"name": "dense", "trainable": True}
                }
            ]
        }
    }
    with h5py.File(file_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SAFE"
    assert result["file_type"] == "hdf5"

def test_malicious_hdf5_lambda(temp_dir):
    file_path = temp_dir / "malicious_lambda.h5"
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "lambda",
                        "function": ["Y29kZQ==", None, None],
                        "function_type": "lambda"
                    }
                }
            ]
        }
    }
    with h5py.File(file_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "MALICIOUS"
    assert result["file_type"] == "hdf5"
    assert any("Contains 1 Keras Lambda layer(s)" in r for r in result["reasons"])

def test_benign_safetensors(temp_dir):
    file_path = temp_dir / "model.safetensors"
    header = {
        "tensor_1": {
            "dtype": "F32",
            "shape": [2],
            "data_offsets": [0, 8]
        }
    }
    header_json = json.dumps(header).encode('utf-8')
    header_size = len(header_json)
    data_bytes = b'\x00\x00\x80?\x00\x00\x00@'
    
    with open(file_path, "wb") as f:
        f.write(struct.pack('<Q', header_size))
        f.write(header_json)
        f.write(data_bytes)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SAFE"
    assert result["file_type"] == "safetensors"

def test_safetensors_appended_payload(temp_dir):
    file_path = temp_dir / "payload_appended.safetensors"
    header = {
        "tensor_1": {
            "dtype": "F32",
            "shape": [2],
            "data_offsets": [0, 8]
        }
    }
    header_json = json.dumps(header).encode('utf-8')
    header_size = len(header_json)
    data_bytes = b'\x00\x00\x80?\x00\x00\x00@'
    malicious_payload = b'X' * 2048
    
    with open(file_path, "wb") as f:
        f.write(struct.pack('<Q', header_size))
        f.write(header_json)
        f.write(data_bytes)
        f.write(malicious_payload)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SUSPICIOUS"
    assert any("extra appended payload data" in r for r in result["reasons"])

def test_benign_gguf(temp_dir):
    file_path = temp_dir / "model.gguf"
    with open(file_path, "wb") as f:
        f.write(b'GGUF')
        f.write(struct.pack('<IQQ', 3, 10, 2))
        f.write(b'\x00' * 64)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SAFE"
    assert result["file_type"] == "gguf"
    assert "Valid GGUF v3 model" in result["reasons"][0]

def test_malicious_onnx_traversal(temp_dir):
    file_path = temp_dir / "model.onnx"
    with open(file_path, "wb") as f:
        f.write(b'\x08\x03\x12\x07onnx.ai\x1a\x10external_data: ../../../etc/passwd')
        
    result = scan_file(str(file_path))
    assert result["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    assert any("external data path reference" in r for r in result["reasons"])

def test_benign_numpy(temp_dir):
    file_path = temp_dir / "array.npy"
    header_dict = "{'descr': '<f8', 'fortran_order': False, 'shape': (2, 2)}"
    header_bytes = header_dict.encode('latin1')
    with open(file_path, "wb") as f:
        f.write(b'\x93NUMPY\x01\x00')
        f.write(struct.pack('<H', len(header_bytes)))
        f.write(header_bytes)
        f.write(b'\x00' * 32)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SAFE"
    assert result["file_type"] == "numpy"

def test_embedded_exe_payload(temp_dir):
    file_path = temp_dir / "embedded_exe.bin"
    with open(file_path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 100) # PE magic header
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SUSPICIOUS"
    assert any("Embedded Windows Portable Executable" in r for r in result["reasons"])

def test_sarif_export(temp_dir):
    results = [
        {
            "filepath": "malicious.pkl",
            "file_type": "pickle",
            "verdict": "MALICIOUS",
            "risk_score": 9.5,
            "severity": "CRITICAL",
            "reasons": ["Blocked reference: 'os.system'"]
        }
    ]
    sarif_path = temp_dir / "output.sarif"
    export_sarif_report(results, str(sarif_path))
    
    assert os.path.exists(sarif_path)
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1

def test_config_loader(temp_dir):
    config_file = temp_dir / ".modelsentryrc"
    config_data = {
        "threads": 8,
        "min_severity": "MEDIUM"
    }
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f)
        
    loaded = load_config_file(str(config_file))
    assert loaded["threads"] == 8
    assert loaded["min_severity"] == "MEDIUM"

def test_ignore_file_suppression(temp_dir):
    import os as local_os
    file_path = temp_dir / "malicious_ignored.pkl"
    malicious_obj = MockMaliciousReduce(local_os.system, ("echo 'hack'",))
    with open(file_path, "wb") as f:
        pickle.dump(malicious_obj, f)
        
    ignore_file = temp_dir / ".modelsentryignore"
    with open(ignore_file, "w", encoding="utf-8") as f:
        f.write("# Ignore rules\n")
        f.write("os.system\n")
        
    result = scan_file(str(file_path), ignore_file=str(ignore_file))
    assert result["verdict"] == "SAFE"
    assert "suppressed" in result["reasons"][0].lower()

def test_init_git_hook(temp_dir, monkeypatch):
    monkeypatch.chdir(temp_dir)
    os.makedirs(".git", exist_ok=True)
    success = init_pre_commit_hook(force=True)
    assert success is True
    hook_file = temp_dir / ".git" / "hooks" / "pre-commit"
    assert os.path.exists(hook_file)
    with open(hook_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "ModelSentry Pre-Commit Check" in content

def test_hf_repo_parser(monkeypatch):
    fake_tree = [
        {"path": "config.json", "type": "file"},
        {"path": "model.safetensors", "type": "file"},
        {"path": "pytorch_model.bin", "type": "file"}
    ]
    class MockResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            return json.dumps(fake_tree).encode('utf-8')

    def mock_urlopen(req):
        return MockResponse()

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
    monkeypatch.setattr("modelsentry.handle_url_scan", lambda u, *args, **kw: {"filepath": u, "verdict": "SAFE", "reasons": ["Mock clean"]})

    results = handle_hf_scan("fake/repo", is_json=True)
    assert len(results) == 2
    assert any("model.safetensors" in r["filepath"] for r in results)

def test_expanded_blocklist(temp_dir):
    file_path = temp_dir / "blocked_module.pkl"
    pickle_bytes = b"cwinreg\nOpenKey\n(I1\ntR."
    with open(file_path, "wb") as f:
        f.write(pickle_bytes)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "MALICIOUS"
    assert any("winreg" in r for r in result["reasons"])

