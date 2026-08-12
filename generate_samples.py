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
            # Safe representation of code execution risk using print
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
    st_data = b'\x00\x00\x80?\x00\x00\x00@' # float32: [1.0, 2.0]
    
    with open("SAMPLES/benign_safetensors.safetensors", "wb") as f:
        f.write(struct.pack('<Q', st_header_size))
        f.write(st_header_bytes)
        f.write(st_data)
        
    # 6. Malicious Safetensors (appended extra payload bytes at the end)
    print("Generating SAMPLES/malicious_safetensors.safetensors...")
    # Header claims data ends at byte 8, but we write 2048 bytes of extra payload after that.
    payload = b'MALICIOUS_EXECUTABLE_OR_SHELLCODE_HERE' + b'\x00' * 2000
    with open("SAMPLES/malicious_safetensors.safetensors", "wb") as f:
        f.write(struct.pack('<Q', st_header_size))
        f.write(st_header_bytes)
        f.write(st_data)
        f.write(payload)
        
    print("All samples generated successfully under SAMPLES/ directory.")

if __name__ == "__main__":
    main()
