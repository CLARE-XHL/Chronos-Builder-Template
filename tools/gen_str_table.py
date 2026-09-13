#!/usr/bin/env python3
"""
Chronos Seal - 字符串加密表生成工具

用法（CI 环境）:
    由 build.yml 调用，输出到 native/src/cs_str_table.h

用法（本地手动）:
    python tools/gen_str_table.py > native/src/cs_str_table.h

生成的头文件包含:
    - 每个 tag 的密文字节数组（inline constexpr，多 TU 共享一份）
    - 每个 tag 的 32 位 LCG 流密钥 seed
    - cs_decode() 内联函数
    - CS_DECODE_XXX() 便捷宏

设计说明:
    - seed 由 tag 明文的 FNV-1a 哈希派生（32 位），可选混入 CS_BUILD_SALT
    - 流密钥逐字节变化：s = s * 1664525 + 1013904223，字节取自 (s >> 16) & 0xFF
    - 单字节 8 位 key 会被秒破，32 位流密钥暴力空间 4G，且无法用首字节剪枝
    - 本文件中的 tag 明文列表是**已知暴露面**：防御目标是"二进制不暴露指纹"，
      不是"保护算法结构"。真正的秘密是 SEED_A ~ SEED_D，不在本脚本里。

环境变量:
    CS_BUILD_SALT   可选，整数（支持 0x 前缀）。默认 0。
                    混入 seed 派生，让不同构建的密文不同。
                    本轮默认不启用；将来想开，在 build.yml 里传值即可。
"""

import os
import sys

# 可选 build salt：默认 0（不启用）
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
    """由明文派生 32 位 seed。FNV-1a 32-bit，可选混入 build_salt。"""
    h = 0x811C9DC5
    for b in plain.encode('utf-8'):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    h ^= build_salt & 0xFFFFFFFF
    return h if h != 0 else 1


def encode(plain: str, seed: int):
    """LCG 流密钥逐字节 XOR 编码。必须与 C++ cs_decode 严格一致。"""
    out = []
    s = seed
    for c in plain.encode('utf-8'):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append(c ^ ((s >> 16) & 0xFF))
    return out


def main():
    out = sys.stdout

    out.write("// ============================================================\n")
    out.write("// 自动生成，请勿手动编辑\n")
    out.write("// 生成工具: tools/gen_str_table.py\n")
    out.write("// 重新生成: python tools/gen_str_table.py > native/src/cs_str_table.h\n")
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
