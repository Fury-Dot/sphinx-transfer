/* ================================================================
   asm/fury.c  —  Master Compilation Unit for SecureTransfer
   ================================================================
   Includes all C components for single-command shared library build.
   Use this for Render or local compilation:
   gcc -shared -o fury.so -fPIC fury.c -O2
   ================================================================ */

#include "wrapper.c"
#include "pbkdf2.c"
#include "hmac-sha256.c"
#include "sha256.c"
#include "fallback.c"
