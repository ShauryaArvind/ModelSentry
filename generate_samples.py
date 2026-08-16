import os
import json
import struct
import pickle
import h5py

def main():
    os.makedirs("SAMPLES", exist_ok=True)
    
    # 1. Benign Pickle
    print("Generating SAMPLES/benign_pickle.pkl...")
    benign_data = {"weights": [0.15, -0.82, 0.94], "bias": [0.0]}
    with open("SAMPLES/benign_pickle.pkl", "wb") as f:
        pickle.dump(benign_data, f)
        
    # 2. Malicious Pickle (deliberately calling builtins.print)
    print("Generating SAMPLES/malicious_pickle.pkl...")
    class MaliciousReduce:
        def __reduce__(self):
            return (print, ("⚠️ Alert: This model is calling an executable function!",))
            
    with open("SAMPLES/malicious_pickle.pkl", "wb") as f:
        pickle.dump(MaliciousReduce(), f)
        
    # 3. Benign HDF5
    print("Generating SAMPLES/benign_hdf5.h5...")
    benign_config = {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {"name": "dense_1", "trainable": True}
                }
            ]
        }
    }
    with h5py.File("SAMPLES/benign_hdf5.h5", "w") as f:
        f.attrs["model_config"] = json.dumps(benign_config)
        
    # 4. Malicious HDF5 (Lambda layer)
    print("Generating SAMPLES/malicious_hdf5.h5...")
    malicious_config = {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "malicious_lambda",
                        "function": ["Y29kZQ==", None, None],
                        "function_type": "lambda"
                    }
                }
            ]
        }
    }
    with h5py.File("SAMPLES/malicious_hdf5.h5", "w") as f:
        f.attrs["model_config"] = json.dumps(malicious_config)
        
    # 5. Benign Safetensors
    print("Generating SAMPLES/benign_safetensors.safetensors...")
    st_header = {
        "embeddings": {
            "dtype": "F32",
            "shape": [2],
            "data_offsets": [0, 8]
        }
    }
    st_header_bytes = json.dumps(st_header).encode('utf-8')
    st_header_size = len(st_header_bytes)
    st_data = b'\x00\x00\x80?\x00\x00\x00@'
    
    with open("SAMPLES/benign_safetensors.safetensors", "wb") as f:
        f.write(struct.pack('<Q', st_header_size))
        f.write(st_header_bytes)
        f.write(st_data)
        
    # 6. Malicious Safetensors (appended payload bytes)
    print("Generating SAMPLES/malicious_safetensors.safetensors...")
    payload = b'MALICIOUS_EXECUTABLE_OR_SHELLCODE_HERE' + b'\x00' * 2000
    with open("SAMPLES/malicious_safetensors.safetensors", "wb") as f:
        f.write(struct.pack('<Q', st_header_size))
        f.write(st_header_bytes)
        f.write(st_data)
        f.write(payload)
        
    # 7. Benign GGUF
    print("Generating SAMPLES/benign_gguf.gguf...")
    with open("SAMPLES/benign_gguf.gguf", "wb") as f:
        f.write(b'GGUF') # Magic
        f.write(struct.pack('<IQQ', 3, 12, 4)) # Version 3, 12 tensors, 4 kv pairs
        f.write(b'\x00' * 128)
        
    # 8. Benign ONNX
    print("Generating SAMPLES/benign_onnx.onnx...")
    with open("SAMPLES/benign_onnx.onnx", "wb") as f:
        f.write(b'\x08\x03\x12\x07onnx.ai\x1a\x10graph_definition')
        
    # 9. Malicious ONNX (path traversal attempt)
    print("Generating SAMPLES/malicious_onnx.onnx...")
    with open("SAMPLES/malicious_onnx.onnx", "wb") as f:
        f.write(b'\x08\x03\x12\x07onnx.ai\x1a\x10external_data: ../../../etc/passwd')
        
    # 10. Benign NumPy (.npy)
    print("Generating SAMPLES/benign_numpy.npy...")
    header_dict = "{'descr': '<f8', 'fortran_order': False, 'shape': (2, 2)}"
    header_bytes = header_dict.encode('latin1')
    header_len = len(header_bytes)
    with open("SAMPLES/benign_numpy.npy", "wb") as f:
        f.write(b'\x93NUMPY\x01\x00')
        f.write(struct.pack('<H', header_len))
        f.write(header_bytes)
        f.write(b'\x00' * 32)
        
    print("All sample files successfully generated in SAMPLES/ directory.")

if __name__ == "__main__":
    main()
