import os
import customtkinter as ctk
from crypto_engine import ASMBridge, CryptoEngine
from history import TransferHistory
from app import CryptoApp


def main():
    ctk.set_appearance_mode("light")
    lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asm", "fury.so")
    asm     = ASMBridge(lib_path=lib_path)
    engine  = CryptoEngine(asm, iterations=100_000, key_size=32)
    history = TransferHistory()
    root = ctk.CTk()
    CryptoApp(root, engine, history)
    root.mainloop()


if __name__ == "__main__":
    main()