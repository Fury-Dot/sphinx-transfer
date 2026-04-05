import io
import sys
import os

# Add parent directory to path since api is a subfolder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.server import app

def run_test():
    client = app.test_client()
    
    # 1. Test Health (Check ASM)
    resp = client.get('/api/health')
    assert resp.status_code == 200, f"Health check failed: {resp.status_code}"
    data = resp.get_json()
    assert data['asm'] is True, "ASM should be active after compilation!"
    print("✓ Health check ok (ASM: ACTIVE)")

    # 2. Test Encrypt
    original_data = b"Hello SecureTransfer Web Test payload." * 1024 # 36KB
    data = {"password": "TestPassword123!", "file": (io.BytesIO(original_data), "test_file.txt")}
    
    resp = client.post('/api/encrypt', data=data, content_type='multipart/form-data')
    assert resp.status_code == 200, f"Encrypt failed: {resp.status_code} {resp.data}"
    
    enc_data = resp.data
    assert len(enc_data) > len(original_data), "Encrypted data should be larger than original (salt+nonce+tag)"
    print(f"✓ Encrypt successful (Original: {len(original_data)}b, Encrypted: {len(enc_data)}b)")
    
    # Check headers
    assert "X-PBKDF2-Ms" in resp.headers
    assert "X-HMAC" in resp.headers
    print("✓ Headers verified")

    # 3. Test Decrypt
    dec_req_data = {"password": "TestPassword123!", "file": (io.BytesIO(enc_data), "test_file.txt.enc")}
    
    resp_dec = client.post('/api/decrypt', data=dec_req_data, content_type='multipart/form-data')
    assert resp_dec.status_code == 200, f"Decrypt failed: {resp_dec.status_code} {resp_dec.data}"
    
    dec_data = resp_dec.data
    assert dec_data == original_data, "Decrypted data does not match original data!"
    print("✓ Decrypt successful and matched perfectly!")

    # 4. Test Benchmark
    resp = client.post('/api/benchmark', json={"type": "perf"})
    assert resp.status_code == 200
    bench_data = resp.get_json()
    assert len(bench_data['results']) == 3
    assert bench_data['asm_active'] is True
    print("✓ Benchmarks (Perf) ok")

if __name__ == '__main__':
    run_test()
    print("ALL TESTS PASSED")
