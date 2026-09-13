#!/usr/bin/env python3
"""
Chronos Seal - String encryption table generator

Usage:
    python tools/gen_str_table.py > native/src/cs_str_table.h

Generates:
    - ciphertext byte array for each tag (compile-time constant)
    - 32-bit LCG stream-key seed per tag
    - inline cs_decode() function
    - CS_DECODE_XXX() convenience macros

Design notes:
    - seed derived from tag plaintext via FNV-1a 32-bit, optionally XORed with CS_BUILD_SALT
    - stream key per byte: s = s * 1664525 + 1013904223; byte = (s >> 16) & 0xFF
    - 8-bit single key is brute-forceable in seconds; 32-bit stream key is not
    - The tag plaintext list below is a KNOWN EXPOSED SURFACE. It is metadata for the
      key derivation path, not the key itself. The real secret is SEED_A ~ SEED_D
      (not in this file).

Environment variables:
    CS_BUILD_SALT   Optional, integer (0x prefix allowed). Default 0.
                    Mixed into seed derivation to make ciphertext per-build unique.
                    Currently disabled by default; enable in build.yml if needed.

Note:
    Output is pure ASCII to avoid Windows cp1252 stdout encoding issues.
"""

import os
import sys

# Defensive: force UTF-8 on stdout (Windows defaults to cp1252 otherwise)
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# Optional build salt: default 0 (disabled)
try:
    BUILD_SALT = int(os.environ.get('CS_BUILD_SALT', '0'), 0) & 0xFFFFFFFF
except ValueError:
    BUILD_SALT = 0

TAGS = [
    ("CS_TAG_MASTER",       "MASTER:"),
    ("CS_TAG_STAGE2",       "STAGE2:"),
    ("CS_TAG_STAGE3",       "STAGE3:"),
    ("CS_TAG_MASTER_FINAL", "MASTER:FINAL"),
    ("CS_TAG_AES_S1",       "AES:S1:"),
    ("CS_TAG_AES_S2",       "AES:S2:"),
    ("CS_TAG_AES_S3",       "AES:S3:"),
    ("CS_TAG_AES_FINAL",    "AES:FINAL:"),
    ("CS_TAG_HMAC_S1",      "HMAC:S1:"),
    ("CS_TAG_HMAC_S2",      "HMAC:S2:"),
    ("CS_TAG_HMAC_S3",      "HMAC:S3:"),
    ("CS_TAG_HMAC_FINAL",   "HMAC:FINAL:"),
    ("CS_TAG_AUX_KEY",      "gamma_key_material_do_not_use"),
    ("CS_TAG_RUNTIME_ENV",  "CS_RUNTIME_MODE"),
]


def fnv1a_seed(plain: str, build_salt: int) -> int:
    """Derive 32-bit seed from plaintext. FNV-1a 32-bit, optionally XORed with build_salt."""
    h = 0x811C9DC5
    for b in plain.encode('utf-8'):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    h ^= build_salt & 0xFFFFFFFF
    return h if h != 0 else 1


def encode(plain: str, seed: int):
    """LCG stream-key byte-wise XOR encoding. Must match C++ cs_decode exactly."""
    out = []
    s = seed
    for c in plain.encode('utf-8'):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append(c ^ ((s >> 16) & 0xFF))
    return out


def main():
    out = sys.stdout

    out.write("// ============================================================\n")
    out.write("// Auto-generated. Do not edit manually.\n")
    out.write("// Generator: tools/gen_str_table.py\n")
    out.write("// Regenerate: python tools/gen_str_table.py > native/src/cs_str_table.h\n")
    out.write("// ============================================================\n")
    out.write("\n")
    out.write("#pragma once\n")
    out.write("#include <cstddef>\n")
    out.write("#include <cstdint>\n")
    out.write("#include <string>\n")
    out.write("\n")

    for const_name, plain in TAGS:
        seed = fnv1a_seed(plain, BUILD_SALT)
        enc = encode(plain, seed)
        arr_name = const_name + "_ENC"
        seed_name = const_name + "_SEED"

        out.write(f"inline constexpr uint8_t {arr_name}[] = {{\n")
        line = "   "
        for i, b in enumerate(enc):
            line += f" 0x{b:02X},"
            if (i + 1) % 12 == 0:
                out.write(line.rstrip() + "\n")
                line = "   "
        if line.strip():
            out.write(line.rstrip() + "\n")
        out.write("};\n")
        out.write(f"inline constexpr uint32_t {seed_name} = 0x{seed:08X}u;\n")
        out.write("\n")

    out.write("inline std::string cs_decode(const uint8_t* enc, size_t len, uint32_t seed) {\n")
    out.write("    std::string out;\n")
    out.write("    out.resize(len);\n")
    out.write("    uint32_t s = seed;\n")
    out.write("    for (size_t i = 0; i < len; ++i) {\n")
    out.write("        s = s * 1664525u + 1013904223u;\n")
    out.write("        out[i] = static_cast<char>(enc[i] ^ ((s >> 16) & 0xFF));\n")
    out.write("    }\n")
    out.write("    return out;\n")
    out.write("}\n")
    out.write("\n")

    for const_name, _ in TAGS:
        short = const_name[len("CS_TAG_"):]
        arr_name = const_name + "_ENC"
        seed_name = const_name + "_SEED"
        out.write(f"#define CS_DECODE_{short}() \\\n")
        out.write(f"    cs_decode({arr_name}, sizeof({arr_name}), {seed_name})\n")


if __name__ == "__main__":
    main()
