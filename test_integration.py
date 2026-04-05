import os
import time
import socket
import threading
import hashlib
from crypto_engine import ASMBridge, CryptoEngine
from network import receive_file_tcp, send_file_tcp

def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def main():
    print("=== SecureTransfer Integration Test ===")
    
    # 1. Generate test data
    test_src = "test_source.dat"
    test_enc = "test_encrypted.enc"
    test_recv_dir = "test_recv_dir"
    test_dec = "test_decrypted.dat"
    test_pw = "supersecret123"
    
    os.makedirs(test_recv_dir, exist_ok=True)
    
    print("Generating 5MB test file...")
    data = os.urandom(5 * 1024 * 1024)
    with open(test_src, "wb") as f:
        f.write(data)
    orig_hash = hashlib.sha256(data).hexdigest()
    
    # 2. Setup Crypto Engine
    print("Setting up crypto engine...")
    lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asm", "fury.so")
    asm = ASMBridge(lib_path=lib_path)
    # Use smaller iterations for test speed
    engine = CryptoEngine(asm, iterations=1000, key_size=32)

    # 3. Encrypt
    print("Encrypting...")
    engine.encrypt_stream(test_src, test_enc, test_pw)

    # 4. Setup Receiver
    port = find_free_port()
    print(f"Starting receiver on port {port}...")
    
    recv_result = {}
    
    def receiver_thread():
        try:
            out_path, filename, t = receive_file_tcp(port, test_recv_dir)
            recv_result['out_path'] = out_path
            recv_result['filename'] = filename
        except Exception as e:
            recv_result['error'] = e

    rt = threading.Thread(target=receiver_thread)
    rt.start()
    
    # Give the receiver a moment to start listening
    time.sleep(0.5)

    # 5. Send
    print("Sending...")
    send_file_tcp("127.0.0.1", port, "test_encrypted.enc", test_enc)
    
    rt.join(timeout=5.0)
    
    if 'error' in recv_result:
        raise recv_result['error']
        
    received_file = recv_result['out_path']
    print(f"Received file at: {received_file}")

    # 6. Decrypt
    print("Decrypting...")
    engine.decrypt_stream(received_file, test_dec, test_pw)

    # 7. Verify
    print("Verifying...")
    with open(test_dec, "rb") as f:
        dec_data = f.read()
    dec_hash = hashlib.sha256(dec_data).hexdigest()
    
    if orig_hash == dec_hash:
        print("SUCCESS! Hashes match perfectly.")
        
        # Cleanup
        os.remove(test_src)
        os.remove(test_enc)
        os.remove(received_file)
        os.remove(test_dec)
        os.rmdir(test_recv_dir)
    else:
        print("FAIL! Hashes do not match.")
        print(f"Original: {orig_hash}")
        print(f"Decrypted: {dec_hash}")
        raise ValueError("Hash mismatch")

if __name__ == "__main__":
    main()
