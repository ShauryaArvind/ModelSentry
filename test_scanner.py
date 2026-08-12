import os
import json
import struct
import pickle
import zipfile
import pytest
import h5py
from scanner import scan_file, extract_pickle_calls_from_bytes, validate_safetensors

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

def test_malicious_pickle_blocked(temp_dir):
    import os as local_os
    file_path = temp_dir / "malicious_blocked.pkl"
    # Using os.system
    malicious_obj = MockMaliciousReduce(local_os.system, ("echo 'hack'",))
    with open(file_path, "wb") as f:
        pickle.dump(malicious_obj, f)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "MALICIOUS"
    assert any("Blocked reference:" in r and "system" in r for r in result["reasons"])

def test_suspicious_pickle_unknown(temp_dir):
    file_path = temp_dir / "suspicious.pkl"
    # Reference a dummy custom function not in allowlist or blocklist
    # We can write a custom reference using pickle's GLOBAL opcode simulation
    # Or just pickle a function from a non-standard module if it's importable.
    # To be fully deterministic, we construct a raw pickle byte string:
    # c module\n name\n. -> GLOBAL opcode
    pickle_bytes = b"cmy_custom_module\nmy_function\n(I1\ntR." # calls my_custom_module.my_function(1)
    with open(file_path, "wb") as f:
        f.write(pickle_bytes)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "SUSPICIOUS"
    assert any("Unknown/unverified reference: 'my_custom_module.my_function'" in r for r in result["reasons"])

def test_pytorch_zip_malicious(temp_dir):
    file_path = temp_dir / "pytorch_model.pt"
    
    # Create a mock PyTorch ZIP archive
    # Inside PyTorch files, the pickle is stored under archive/data.pkl
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
                        "function": ["Y29kZQ==", None, None], # base64 bytecode representation
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
    # Structure of safetensors manually constructed:
    header = {
        "tensor_1": {
            "dtype": "F32",
            "shape": [2],
            "data_offsets": [0, 8]
        }
    }
    header_json = json.dumps(header).encode('utf-8')
    header_size = len(header_json)
    
    # 8 bytes header size, then header JSON, then 8 bytes of raw data
    data_bytes = b'\x00\x00\x80?\x00\x00\x00@' # 2 floats: 1.0, 2.0
    
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
    
    # Data is 8 bytes, but we append 2048 extra bytes at the end
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

def test_safetensors_truncated(temp_dir):
    file_path = temp_dir / "truncated.safetensors"
    header = {
        "tensor_1": {
            "dtype": "F32",
            "shape": [2],
            "data_offsets": [0, 8]
        }
    }
    header_json = json.dumps(header).encode('utf-8')
    header_size = len(header_json)
    
    # We write only 4 bytes of data instead of 8
    data_bytes = b'\x00\x00\x80?'
    
    with open(file_path, "wb") as f:
        f.write(struct.pack('<Q', header_size))
        f.write(header_json)
        f.write(data_bytes)
        
    result = scan_file(str(file_path))
    assert result["verdict"] == "MALICIOUS"
    assert any("truncated by 4 bytes" in r for r in result["reasons"])
