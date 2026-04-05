# ═══════════════════════════════════════════════
#  api/app.py  —  Flask Web Backend for SecureTransfer
# ═══════════════════════════════════════════════

import os
import sys
import uuid
import tempfile
import hashlib
import hmac as hmac_mod
import time
import struct

from flask import Flask, request, send_file, render_template, jsonify

# Add parent directory to path so we can import crypto_engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto_engine import CryptoEngine, ASMBridge, aes_ctr_crypt, _aes_encrypt_block

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB upload limit

# Initialize engine with C acceleration support
lib_path = os.path.join(os.path.dirname(__file__), "..", "asm", "fury.so")
asm = ASMBridge(lib_path=lib_path)
engine = CryptoEngine(asm, iterations=100_000, key_size=32)

UPLOAD_DIR = tempfile.mkdtemp(prefix="securetransfer_")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt an uploaded file with the given password."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    password = request.form.get("password", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # Save upload to temp
    src_name = f"{uuid.uuid4().hex}"
    src_path = os.path.join(UPLOAD_DIR, src_name)
    out_path = os.path.join(UPLOAD_DIR, src_name + ".enc")

    try:
        file.save(src_path)
        file_size = os.path.getsize(src_path)

        # Encrypt using the existing streaming engine
        timings = engine.encrypt_stream(src_path, out_path, password)

        out_size = os.path.getsize(out_path)
        original_name = file.filename + ".enc"

        response = send_file(
            out_path,
            as_attachment=True,
            download_name=original_name,
            mimetype="application/octet-stream"
        )

        # Add timing headers for the frontend
        response.headers["X-PBKDF2-Ms"] = str(timings.get("pbkdf2_ms", ""))
        response.headers["X-AES-Ms"] = str(timings.get("aes_ctr_ms", ""))
        response.headers["X-HMAC"] = str(timings.get("hmac_ms", ""))
        response.headers["X-Original-Size"] = str(file_size)
        response.headers["X-Encrypted-Size"] = str(out_size)

        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        # Cleanup temp files
        for p in [src_path, out_path]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """Decrypt an uploaded .enc file with the given password."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    password = request.form.get("password", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    src_name = f"{uuid.uuid4().hex}"
    src_path = os.path.join(UPLOAD_DIR, src_name + ".enc")
    out_path = os.path.join(UPLOAD_DIR, src_name + ".dec")

    try:
        file.save(src_path)

        # Decrypt using the existing streaming engine
        timings = engine.decrypt_stream(src_path, out_path, password)

        # Strip .enc from original filename for download
        original_name = file.filename
        if original_name.endswith(".enc"):
            original_name = original_name[:-4]

        response = send_file(
            out_path,
            as_attachment=True,
            download_name=original_name,
            mimetype="application/octet-stream"
        )

        response.headers["X-PBKDF2-Ms"] = str(timings.get("pbkdf2_ms", ""))
        response.headers["X-AES-Ms"] = str(timings.get("aes_ctr_ms", ""))
        response.headers["X-HMAC"] = str(timings.get("hmac_ms", ""))

        return response

    except ValueError as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        for p in [src_path, out_path]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


@app.route("/api/benchmark", methods=["POST"])
def api_benchmark():
    """Run a performance benchmark similar to the desktop app."""
    data = request.json or {}
    bench_type = data.get("type", "perf")  # perf, iters, keysize

    try:
        results = []
        if bench_type == "perf":
            # Test different file sizes
            for size_mb in [1, 5, 20]:
                test_data = os.urandom(size_mb * 1024 * 1024)
                _, timings = engine.encrypt(test_data, "benchmarking")
                results.append({
                    "label": f"{size_mb} MB",
                    "pbkdf2_ms": timings["pbkdf2_ms"],
                    "aes_ctr_ms": timings["aes_ctr_ms"],
                    "hmac_ms": timings["hmac_ms"]
                })
        elif bench_type == "iters":
            # Test different iterations
            test_data = os.urandom(5 * 1024 * 1024) # 5MB
            orig_iters = engine.iterations
            for iters in [10_000, 100_000, 250_000, 500_000]:
                engine.iterations = iters
                _, timings = engine.encrypt(test_data, "benchmarking")
                results.append({
                    "label": f"{iters:,} iters",
                    "pbkdf2_ms": timings["pbkdf2_ms"],
                    "aes_ctr_ms": timings["aes_ctr_ms"],
                    "hmac_ms": timings["hmac_ms"]
                })
            engine.iterations = orig_iters
        elif bench_type == "keysize":
            # Test different key sizes
            test_data = os.urandom(5 * 1024 * 1024) # 5MB
            orig_ks = engine.key_size
            for ks_name, ks_val in [("128-bit", 16), ("192-bit", 24), ("256-bit", 32)]:
                engine.key_size = ks_val
                _, timings = engine.encrypt(test_data, "benchmarking")
                results.append({
                    "label": ks_name,
                    "pbkdf2_ms": timings["pbkdf2_ms"],
                    "aes_ctr_ms": timings["aes_ctr_ms"],
                    "hmac_ms": timings["hmac_ms"]
                })
            engine.key_size = orig_ks

        return jsonify({
            "type": bench_type,
            "results": results,
            "asm_active": asm.using_asm
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "asm": asm.using_asm,
        "engine": "CryptoEngine",
        "iterations": engine.iterations,
        "key_size": engine.key_size,
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
