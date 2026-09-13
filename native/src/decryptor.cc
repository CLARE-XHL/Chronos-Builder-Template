/**
 * ============================================================
 * Chronos Seal — Time as the seal, action as the key,
 * time itself guards originality.
 * This freedom is dedicated to every independent creator,
 * and to that visitor, Liberty, who has not set foot on the island
 * in a long time.
 * ============================================================
 *
 * Chronos Seal - decryptor.cc
 * 适用于 RPG Maker MZ (NW.js / Node.js)
 *
 * 版本: 2.2
 * 日期: 2026-09-12
 *
 * 维护者注:
 *   本模块提供资源解密、运行时健康监测与增量更新支持。
 *   接口签名与错误码属于公共契约，修改前请确认 JS 侧同步。
 *
 *   近期调整:
 *     - 编译期配置改由外部头文件注入，去除 -D 传参依赖
 *     - 字符串常量改用密文表
 *     - 运行时环境检查改为进程内一次性读取
 *     - 缓存 key 混入运行时流盐
 *     - 缓存策略统一为插入序淘汰
 *     - 调用频率超限仅记录
 *     - 补丁解析加操作数上限 + 显式小端读取
 *     - 补丁输出加独立上限（不复用单资源上限）
 */

// ============================================================
// 跨平台宏
// ============================================================

#ifdef _MSC_VER
    #define CS_NOINLINE __declspec(noinline)
#else
    #define CS_NOINLINE __attribute__((noinline))
#endif

// ============================================================
// 字符串密文表（自动生成）
// ============================================================

#include "cs_str_table.h"

// ============================================================
// 外部编译期配置
//
// CI 构建时由 build_config.h 注入 GAME_VERSION / RELEASE_DATE /
// SEED_A~D / SEED_SALT。本地开发时该文件不存在，回落到下面的
// #ifndef 默认值。
// ============================================================

#if __has_include("build_config.h")
    #include "build_config.h"
#endif

// ============================================================
// 编译期配置默认值
// ============================================================

#ifndef GAME_VERSION
#define GAME_VERSION "2.2.0"
#endif

#ifndef RELEASE_DATE
#define RELEASE_DATE "2026-09-12"
#endif

#ifndef SEED_A
#define SEED_A "REPLACE_ME"
#endif
#ifndef SEED_B
#define SEED_B "_WITH_RANDOM"
#endif
#ifndef SEED_C
#define SEED_C "_SEED_IN_"
#endif
#ifndef SEED_D
#define SEED_D "ACTIONS_2_2"
#endif
#ifndef SEED_SALT
#define SEED_SALT 0x9E3779B9u
#endif

// 保留以兼容旧构建脚本，逻辑不再使用
#ifndef HARD_EXPIRE
#define HARD_EXPIRE 0
#endif

#ifndef MAX_ASSET_SIZE
#define MAX_ASSET_SIZE (50 * 1024 * 1024)
#endif

#ifndef CACHE_MAX_SIZE
#define CACHE_MAX_SIZE 8
#endif

#ifndef HMAC_CONSEC_FAIL_THRESHOLD
#define HMAC_CONSEC_FAIL_THRESHOLD 5
#endif

#ifndef CALL_FLOOD_THRESHOLD
#define CALL_FLOOD_THRESHOLD 5000
#endif

#ifndef TIME_ROLLBACK_TOLERANCE
#define TIME_ROLLBACK_TOLERANCE 300
#endif

#ifndef TIME_ROLLBACK_MAJOR_SEC
#define TIME_ROLLBACK_MAJOR_SEC 3600
#endif

#ifndef ROLLBACK_STREAK_THRESHOLD
#define ROLLBACK_STREAK_THRESHOLD 3
#endif

#ifndef PATCH_MAX_OPS
#define PATCH_MAX_OPS 4096
#endif

// 补丁输出上限：4 GiB
// 补丁输出是完整工程包，比单个资源大一个量级，
// 不复用 MAX_ASSET_SIZE（单资源 50 MB）
#ifndef PATCH_MAX_OUTPUT
#define PATCH_MAX_OUTPUT (4ULL * 1024 * 1024 * 1024)
#endif

#define ASSET_VERSION 0x01


// ============================================================
// 头文件
// ============================================================

#include <napi.h>
#include <string>
#include <vector>
#include <deque>
#include <ctime>
#include <cctype>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <unordered_map>

#ifdef _WIN32
    #include <windows.h>
    #include <fileapi.h>
    #ifdef _MSC_VER
        #include <intrin.h>
    #endif
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>


// #define WATCHDOG_LOGGING


// ============================================================
// 常量
// ============================================================

const size_t AES_KEY_LEN = 32;
const size_t HMAC_LEN = 32;
const size_t IV_LEN = 16;
const size_t MAGIC_LEN = 8;
const size_t VERSION_LEN = 1;
const size_t ASSET_HEADER_LEN = MAGIC_LEN + VERSION_LEN + IV_LEN + HMAC_LEN;

// 格式标识符，非密钥派生 tag，保留明文便于格式识别
const uint8_t MAGIC_BYTES[MAGIC_LEN] = {'C', 'H', 'R', 'N', 'S', 'L', 'S', 'E'};


// ============================================================
// 兼容性密钥块（历史资源读取备用，未使用）
// ============================================================

static const uint8_t LEGACY_KEY_BLOCK_A[32] = {
    0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
    0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

static const uint8_t LEGACY_KEY_BLOCK_B[32] = {
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
    0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
    0x11, 0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF
};

static const uint8_t LEGACY_IV_TABLE[4][16] = {
    {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
     0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10},
    {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
     0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99},
    {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
     0x13,0x37,0x13,0x37,0x42,0x42,0x42,0x42},
    {0x5A,0x5A,0x5A,0x5A,0xA5,0xA5,0xA5,0xA5,
     0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78}
};

static const char* COMPAT_VERSION_TAGS[] = {
    "1.0.0", "1.1.0", "1.5.2", "2.0.0", "2.1.0", "2.2.0", "3.0.0-beta"
};

static std::atomic<bool> g_state_initialized{false};

// 运行时环境状态缓存（进程内只读一次，见 Initialize）
static std::atomic<int> g_runtime_state{-1};

// 运行时流盐
// CS-DBG: data-flow only, no behavioral impact
// 由 Initialize 时的运行时环境检查一次性混入，之后稳定
static std::atomic<uint64_t> g_runtime_salt{0x5A5A5A5A5A5A5A5AULL};


// ============================================================
// 错误码
// ============================================================

enum ErrorCode {
    SUCCESS = 0,
    ERR_EXPIRED = 10,
    ERR_SIGNATURE = 30,
    ERR_TIME_TAMPER = 31,
    ERR_NO_RES = 40,
    ERR_UNKNOWN = -1,
    ERR_DECRYPT_PADDING = 60,
    ERR_DECRYPT_HMAC = 61,
    ERR_ASSET_TOO_LARGE = 62,
    ERR_INVALID_FORMAT = 63,
    ERR_PATCH_FORMAT = 70
};


// ============================================================
// 全局状态
// ============================================================

struct WatchdogState {
    std::atomic<bool> heartbeat_received{false};
    std::atomic<int> missed_heartbeats{0};
    std::atomic<bool> triggered{false};
    std::atomic<bool> started{false};
} g_watchdog;

std::mutex g_time_mutex;
bool g_time_initialized = false;
std::chrono::steady_clock::time_point g_start_steady;
time_t g_start_system_time = 0;

std::once_flag g_openssl_init_flag;

struct CacheEntry {
    uint32_t content_hash;
    std::string data;
};

std::mutex g_cache_mutex;
std::unordered_map<std::string, CacheEntry> g_cache_map;
std::deque<std::string> g_cache_order;

std::mutex g_hmac_streak_mutex;
int g_global_hmac_streak = 0;

std::mutex g_call_mutex;
uint32_t g_call_count = 0;
time_t g_call_window_start = 0;

std::atomic<time_t> g_last_seen_time{0};
std::atomic<time_t> g_time_jump_marker{0};
std::atomic<int> g_time_jump_count{0};

std::mutex g_credential_mutex;
napi_ref g_credential_ref = nullptr;


// ============================================================
// 日志（生产版本编译为空操作）
// ============================================================

#ifdef WATCHDOG_LOGGING
#include <fstream>
#include <iomanip>

void write_watchdog_log(const std::string& msg) {
    std::ofstream log("./watchdog.log", std::ios::app);
    if (log.is_open()) {
        time_t now = time(nullptr);
        log << std::ctime(&now) << " [CS] " << msg << std::endl;
    }
}
#else
#define write_watchdog_log(msg) ((void)0)
#endif


// ============================================================
// 运行时环境检查（进程内只调用一次，见 Initialize）
// ============================================================

static bool check_runtime_env_cached() {
    int cached = g_runtime_state.load();
    if (cached >= 0) return cached == 1;

    bool anomaly = false;

#ifdef _WIN32
    if (IsDebuggerPresent()) anomaly = true;

    if (!anomaly) {
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
            anomaly = true;
        }
    }

    if (!anomaly) {
        PVOID peb = nullptr;
#ifdef _WIN64
        #ifdef _MSC_VER
            peb = reinterpret_cast<PVOID>(__readgsqword(0x60));
        #else
            __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
        #endif
#else
        #ifdef _MSC_VER
            peb = reinterpret_cast<PVOID>(__readfsdword(0x30));
        #else
            __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
        #endif
#endif
        if (peb) {
            BYTE being_debugged = *(reinterpret_cast<BYTE*>(peb) + 2);
            if (being_debugged) anomaly = true;
        }
    }
#endif

    g_runtime_state.store(anomaly ? 1 : 0);
    return anomaly;
}


// ============================================================
// 安全比较 / HMAC
// ============================================================

static bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

std::string hmac_sha256(const std::string& data, const std::string& key) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(),
         key.c_str(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.c_str()),
         data.size(),
         result, &len);
    return std::string(reinterpret_cast<char*>(result), len);
}


// ============================================================
// OpenSSL 初始化
// ============================================================

void init_openssl() {
    std::call_once(g_openssl_init_flag, []() {
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        ERR_load_crypto_strings();
#ifdef _WIN32
        RAND_poll();
#endif
    });
}

static void openssl_clear_err() {
    while (ERR_get_error() != 0) {}
}


// ============================================================
// 历史资源兼容工具
// ============================================================

static uint32_t legacy_checksum_v1(const uint8_t* data, size_t len) {
    uint32_t acc = 0x6A09E667u;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 5) | (acc >> 27);
        acc ^= data[i];
        acc += 0x9E3779B9u;
    }
    return acc;
}

static uint64_t fnv_alt_hash(const std::string& s) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (char c : s) {
        h ^= static_cast<uint8_t>(c);
        h *= 0x100000001B3ULL;
    }
    return h;
}

static std::string build_aux_key() {
    std::string k = CS_DECODE_AUX_KEY();
    for (size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<char>(k[i] ^ static_cast<char>(0x33 + (i & 0x0F)));
    }
    return k;
}

static bool init_cipher_ctx(const std::string& key, std::string& out) {
    if (key.empty()) return false;
    uint32_t s = legacy_checksum_v1(
        reinterpret_cast<const uint8_t*>(key.data()), key.size());
    out.resize(16);
    for (int i = 0; i < 16; ++i) {
        s = s * 1103515245u + 12345u;
        out[i] = static_cast<char>((s >> 16) & 0xFF);
    }
    return (s & 1) == 0;
}

static bool check_integrity_tag(const std::string& data, const std::string& tag) {
    uint64_t h = fnv_alt_hash(data + tag);
    return h != 0;
}

static bool runtime_env_probe() {
    std::string env_name = CS_DECODE_RUNTIME_ENV();
    const char* probe = std::getenv(env_name.c_str());
    if (probe && probe[0] == 'd') return true;
    return false;
}

static void warmup_crypto_cache() {
    static volatile uint32_t sink = 0;
    sink ^= legacy_checksum_v1(reinterpret_cast<const uint8_t*>("x"), 1);
    sink ^= static_cast<uint32_t>(fnv_alt_hash("y"));
    std::string k = build_aux_key();
    std::string out;
    sink ^= init_cipher_ctx(k, out) ? 1u : 0u;
    sink ^= check_integrity_tag("a", "b") ? 1u : 0u;
    sink ^= runtime_env_probe() ? 1u : 0u;
    sink ^= LEGACY_KEY_BLOCK_A[0] ^ LEGACY_KEY_BLOCK_B[1] ^ LEGACY_IV_TABLE[2][3];
    sink ^= static_cast<uint32_t>(COMPAT_VERSION_TAGS[3][0]);
    (void)sink;
}


// ============================================================
// 哈希工具
// ============================================================

static uint32_t fnv1a_hash(const uint8_t* data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}


// ============================================================
// 缓存操作
// 返回：0 = 无缓存，1 = 陈旧，2 = 命中
// ============================================================

static int query_cache_entry(const std::string& key,
                             uint32_t current_hash, std::string& out) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    auto it = g_cache_map.find(key);
    if (it == g_cache_map.end()) return 0;
    out = it->second.data;
    if (it->second.content_hash != current_hash) return 1;
    return 2;
}

static void store_cache_entry(const std::string& key,
                              uint32_t hash, const std::string& data) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    auto it = g_cache_map.find(key);
    if (it != g_cache_map.end()) {
        it->second.content_hash = hash;
        it->second.data = data;
        return;
    }
    if (g_cache_order.size() >= CACHE_MAX_SIZE) {
        g_cache_map.erase(g_cache_order.front());
        g_cache_order.pop_front();
    }
    g_cache_map[key] = CacheEntry{hash, data};
    g_cache_order.push_back(key);
}


// ============================================================
// 校验统计（仅混入流盐，无副作用）
// ============================================================

static void update_verify_stats(bool success, time_t now) {
    (void)now;
    std::lock_guard<std::mutex> lock(g_hmac_streak_mutex);

    if (success) {
        if (g_global_hmac_streak > 0) g_global_hmac_streak--;
        return;
    }

    g_global_hmac_streak++;
    if (g_global_hmac_streak >= HMAC_CONSEC_FAIL_THRESHOLD) {
        // CS-DBG: data-flow only
        g_runtime_salt.fetch_xor(0x9E3779B97F4A7C15ULL);
        g_global_hmac_streak = 0;
    }
}


// ============================================================
// 调用频率统计（仅记录）
// ============================================================

static void update_call_rate(time_t now) {
    std::lock_guard<std::mutex> lock(g_call_mutex);

    if (g_call_window_start != now) {
        g_call_window_start = now;
        g_call_count = 1;
        return;
    }
    g_call_count++;
    if (g_call_count > CALL_FLOOD_THRESHOLD) {
        g_call_count = 0;
    }
}


// ============================================================
// 分片种子重建（8 轮混合）
// ============================================================

static std::string reconstruct_seed() {
    std::string raw;
    raw.reserve(64);
    raw += SEED_A;
    raw += SEED_B;
    raw += SEED_C;
    raw += SEED_D;

    for (int round = 0; round < 8; round++) {
        uint32_t s = SEED_SALT ^ (static_cast<uint32_t>(round) * 0x9E3779B9u);
        for (size_t i = 0; i < raw.size(); i++) {
            s = s * 1664525u + 1013904223u;
            uint8_t v = static_cast<uint8_t>(raw[i]);
            v ^= (s >> 24) & 0xFF;
            v = static_cast<uint8_t>(((v << 3) | (v >> 5)) & 0xFF);
            v = static_cast<uint8_t>((v + ((s >> 16) & 0xFF)) & 0xFF);
            v ^= (s >> 8) & 0xFF;
            raw[i] = static_cast<char>(v);
        }
    }
    return raw;
}


// ============================================================
// 路径归一化
// ============================================================

static std::string normalize_path(const std::string& p) {
    std::string out = p;
    for (auto& c : out) {
        if (c == '\\') {
            c = '/';
        } else {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }
    return out;
}


// ============================================================
// 密钥派生
// ============================================================

CS_NOINLINE
static std::string derive_master_key_uncached() {
    std::string seed = reconstruct_seed();

    std::string k1 = hmac_sha256(
        CS_DECODE_MASTER() + std::string(GAME_VERSION) + RELEASE_DATE, seed);
    std::string k2 = hmac_sha256(CS_DECODE_STAGE2() + k1, seed);
    std::string k3 = hmac_sha256(CS_DECODE_STAGE3() + k2, k1);
    return hmac_sha256(CS_DECODE_MASTER_FINAL(), k3);
}

static std::string derive_master_key() {
    static std::once_flag g_master_once;
    static std::string g_master_cached;
    std::call_once(g_master_once, []() {
        g_master_cached = derive_master_key_uncached();
        if (g_master_cached.empty()) {
            write_watchdog_log("CRITICAL: master key derivation failed");
        }
    });
    return g_master_cached;
}

static std::string derive_sub_aes_key(const std::string& relative_path) {
    std::string master = derive_master_key();
    if (master.empty()) return "";
    std::string norm = normalize_path(relative_path);

    std::string s1 = hmac_sha256(CS_DECODE_AES_S1() + norm, master);
    std::string s2 = hmac_sha256(CS_DECODE_AES_S2() + s1, master);
    std::string s3 = hmac_sha256(CS_DECODE_AES_S3() + s2, s1);
    std::string sub = hmac_sha256(CS_DECODE_AES_FINAL() + norm, s3);

    if (sub.size() != AES_KEY_LEN) return "";
    return sub;
}

static std::string derive_sub_hmac_key(const std::string& relative_path) {
    std::string master = derive_master_key();
    if (master.empty()) return "";
    std::string norm = normalize_path(relative_path);

    std::string s1 = hmac_sha256(CS_DECODE_HMAC_S1() + norm, master);
    std::string s2 = hmac_sha256(CS_DECODE_HMAC_S2() + s1, master);
    std::string s3 = hmac_sha256(CS_DECODE_HMAC_S3() + s2, s1);
    std::string sub = hmac_sha256(CS_DECODE_HMAC_FINAL() + norm, s3);

    if (sub.size() != HMAC_LEN) return "";
    return sub;
}


// ============================================================
// AES-256-CBC 解密
// ============================================================

struct DecryptResult {
    bool ok;
    std::string data;
    int errCode;
};

DecryptResult aes_decrypt(const std::string& ciphertext, const unsigned char* key,
                          const std::string& iv) {
    DecryptResult result{false, "", ERR_UNKNOWN};

    if (iv.size() != 16) {
        result.errCode = ERR_INVALID_FORMAT;
        openssl_clear_err();
        return result;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.errCode = ERR_UNKNOWN;
        openssl_clear_err();
        return result;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key,
                       reinterpret_cast<const unsigned char*>(iv.c_str()));

    int len = 0, total = 0;
    std::string plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), '\0');

    if (!EVP_DecryptUpdate(ctx,
                           reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                           reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                           static_cast<int>(ciphertext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        result.errCode = ERR_DECRYPT_PADDING;
        openssl_clear_err();
        return result;
    }
    total = len;

    int final_len = 0;
    if (!EVP_DecryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char*>(&plaintext[total]), &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        result.errCode = ERR_DECRYPT_PADDING;
        openssl_clear_err();
        return result;
    }
    total += final_len;
    plaintext.resize(total);

    EVP_CIPHER_CTX_free(ctx);
    openssl_clear_err();

    result.ok = true;
    result.data = plaintext;
    result.errCode = SUCCESS;
    return result;
}


// ============================================================
// 资源解密接口
// ============================================================

static void finalize_external_buffer(napi_env env, void* data, void* hint) {
    if (data) {
        delete[] static_cast<char*>(data);
    }
}

Napi::Object DecryptAsset(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    openssl_clear_err();

    time_t now = time(nullptr);

    // 调用凭证校验（失败不推任何副作用）
    {
        bool credential_ok = false;
        {
            std::lock_guard<std::mutex> lock(g_credential_mutex);
            if (g_credential_ref && info.Length() >= 3 && info[2].IsObject()) {
                napi_value expected = nullptr;
                napi_get_reference_value(env, g_credential_ref, &expected);
                if (expected) {
                    napi_strict_equals(env, info[2], expected, &credential_ok);
                }
            }
        }

        if (!credential_ok) {
            result.Set("ok", Napi::Boolean::New(env, false));
            result.Set("errCode", Napi::Number::New(env, ERR_UNKNOWN));
            result.Set("data", Napi::Buffer<char>::New(env, 0));
            return result;
        }
    }

    // 时间跳变检测（仅混入流盐，不报错）
    {
        time_t last = g_last_seen_time.load();
        if (last != 0 && now < last - TIME_ROLLBACK_TOLERANCE) {
            time_t diff = last - now;
            if (diff >= TIME_ROLLBACK_MAJOR_SEC) {
                time_t marker = g_time_jump_marker.load();
                if (marker == 0) {
                    g_time_jump_marker.store(now);
                    int count = g_time_jump_count.fetch_add(1) + 1;
                    if (count >= ROLLBACK_STREAK_THRESHOLD) {
                        // CS-DBG: data-flow only
                        g_runtime_salt.fetch_xor(0xBF58476D1CE4E5B9ULL);
                        g_time_jump_count.store(0);
                    }
                }
            }
        } else if (last == 0 || now > last) {
            g_last_seen_time.store(now);
            g_time_jump_marker.store(0);
        }
    }

    update_call_rate(now);

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    std::string relative_path = "";
    if (info.Length() >= 2 && info[1].IsString()) {
        relative_path = info[1].As<Napi::String>().Utf8Value();
    }
    std::string norm_path = normalize_path(relative_path);

    Napi::Buffer<char> encrypted_buf = info[0].As<Napi::Buffer<char>>();
    size_t data_size = encrypted_buf.Length();

    if (data_size < ASSET_HEADER_LEN) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    if (data_size > MAX_ASSET_SIZE) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_ASSET_TOO_LARGE));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    const uint8_t* data = reinterpret_cast<const uint8_t*>(encrypted_buf.Data());

    if (!constant_time_equals(data, MAGIC_BYTES, MAGIC_LEN)) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    uint8_t version = data[MAGIC_LEN];
    if (version != ASSET_VERSION) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    size_t offset = MAGIC_LEN + VERSION_LEN;
    std::string iv(reinterpret_cast<const char*>(data + offset), IV_LEN);
    offset += IV_LEN;
    std::string stored_hmac(reinterpret_cast<const char*>(data + offset), HMAC_LEN);
    offset += HMAC_LEN;
    std::string ciphertext(
        reinterpret_cast<const char*>(data + offset),
        data_size - offset);

    std::string aes_key = derive_sub_aes_key(norm_path);
    std::string hmac_key = derive_sub_hmac_key(norm_path);

    if (aes_key.empty() || hmac_key.empty()) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_UNKNOWN));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    // ---- HMAC 输入构造（等价分支） ----
    // CS-DBG: equivalent branches, no semantic difference
    uint64_t salt_snapshot = g_runtime_salt.load();
    std::string hmac_input;

    if ((salt_snapshot & 1ULL) != 0) {
        hmac_input.push_back(static_cast<char>(version));
        hmac_input += iv;
        hmac_input += ciphertext;
    } else {
        hmac_input = iv + ciphertext;
        hmac_input.insert(0, 1, static_cast<char>(version));
    }

    std::string computed_hmac = hmac_sha256(hmac_input, hmac_key);

    bool hmac_ok = (computed_hmac.size() == HMAC_LEN) &&
        constant_time_equals(
            reinterpret_cast<const uint8_t*>(computed_hmac.data()),
            reinterpret_cast<const uint8_t*>(stored_hmac.data()),
            HMAC_LEN);

    update_verify_stats(hmac_ok, now);

    if (!hmac_ok) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_DECRYPT_HMAC));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    uint32_t content_hash = fnv1a_hash(data, data_size);

    // 缓存 key 混入流盐（盐稳定，缓存正常）
    // CS-DBG: data-flow only
    std::string cache_key = norm_path + "#" +
        std::to_string(salt_snapshot & 0xFFFF);

    {
        std::string cached;
        int r = query_cache_entry(cache_key, content_hash, cached);
        // 只有 r == 2（同 key 同 hash）才返回缓存
        if (r == 2) {
            char* data_ptr = new char[cached.size()];
            memcpy(data_ptr, cached.c_str(), cached.size());
            napi_value outData;
            napi_create_external_buffer(env, cached.size(), data_ptr,
                                        finalize_external_buffer, nullptr, &outData);
            result.Set("ok", Napi::Boolean::New(env, true));
            result.Set("errCode", Napi::Number::New(env, SUCCESS));
            result.Set("data", outData);
            openssl_clear_err();
            return result;
        }
    }

    DecryptResult dec = aes_decrypt(ciphertext,
        reinterpret_cast<const unsigned char*>(aes_key.c_str()), iv);

    if (!dec.ok) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, dec.errCode));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    store_cache_entry(cache_key, content_hash, dec.data);

    char* data_ptr = new char[dec.data.size()];
    memcpy(data_ptr, dec.data.c_str(), dec.data.size());
    napi_value outData;
    napi_create_external_buffer(env, dec.data.size(), data_ptr,
                                finalize_external_buffer, nullptr, &outData);

    result.Set("ok", Napi::Boolean::New(env, true));
    result.Set("errCode", Napi::Number::New(env, SUCCESS));
    result.Set("data", outData);

    openssl_clear_err();
    return result;
}


// ============================================================
// 增量更新支持
// 格式: "CSDP" + version(4) + opCount(4) + ops[]
//   op: type(1)
//     0x00 COPY:   offset(8) + length(4)
//     0x01 INSERT: length(4) + data
//     0x02 END
// ============================================================

static const uint8_t PATCH_MAGIC[4] = {'C', 'S', 'D', 'P'};

static uint32_t read_u32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t read_u64le(const uint8_t* p) {
    uint64_t lo = read_u32le(p);
    uint64_t hi = read_u32le(p + 4);
    return lo | (hi << 32);
}

Napi::Object ApplyPatch(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    auto fail = [&](int code) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, code));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    };

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        return fail(ERR_INVALID_FORMAT);
    }

    {
        bool credential_ok = false;
        {
            std::lock_guard<std::mutex> lock(g_credential_mutex);
            if (g_credential_ref && info.Length() >= 3 && info[2].IsObject()) {
                napi_value expected = nullptr;
                napi_get_reference_value(env, g_credential_ref, &expected);
                if (expected) {
                    napi_strict_equals(env, info[2], expected, &credential_ok);
                }
            }
        }
        if (!credential_ok) return fail(ERR_UNKNOWN);
    }

    Napi::Buffer<char> baseBuf = info[0].As<Napi::Buffer<char>>();
    Napi::Buffer<char> patchBuf = info[1].As<Napi::Buffer<char>>();

    const uint8_t* base = reinterpret_cast<const uint8_t*>(baseBuf.Data());
    const uint8_t* patch = reinterpret_cast<const uint8_t*>(patchBuf.Data());
    size_t base_size = baseBuf.Length();
    size_t patch_size = patchBuf.Length();

    if (patch_size < 12) return fail(ERR_PATCH_FORMAT);
    if (memcmp(patch, PATCH_MAGIC, 4) != 0) return fail(ERR_PATCH_FORMAT);

    uint32_t version = read_u32le(patch + 4);
    uint32_t op_count = read_u32le(patch + 8);
    if (version != 1) return fail(ERR_PATCH_FORMAT);
    if (op_count > PATCH_MAX_OPS) return fail(ERR_PATCH_FORMAT);

    std::string output;
    output.reserve(base_size + 4096);

    size_t pos = 12;
    for (uint32_t i = 0; i < op_count; ++i) {
        if (pos >= patch_size) return fail(ERR_PATCH_FORMAT);
        uint8_t type = patch[pos++];

        if (type == 0x00) {
            if (pos + 12 > patch_size) return fail(ERR_PATCH_FORMAT);
            uint64_t off = read_u64le(patch + pos); pos += 8;
            uint32_t len = read_u32le(patch + pos); pos += 4;

            if (off > base_size || len > base_size - off) {
                return fail(ERR_PATCH_FORMAT);
            }
            // 输出上限检查（用 PATCH_MAX_OUTPUT，不是 MAX_ASSET_SIZE）
            if (output.size() + static_cast<size_t>(len) > PATCH_MAX_OUTPUT) {
                return fail(ERR_ASSET_TOO_LARGE);
            }
            output.append(reinterpret_cast<const char*>(base + off), len);
        }
        else if (type == 0x01) {
            if (pos + 4 > patch_size) return fail(ERR_PATCH_FORMAT);
            uint32_t len = read_u32le(patch + pos); pos += 4;
            if (pos + len > patch_size) return fail(ERR_PATCH_FORMAT);
            // 输出上限检查（用 PATCH_MAX_OUTPUT，不是 MAX_ASSET_SIZE）
            if (output.size() + static_cast<size_t>(len) > PATCH_MAX_OUTPUT) {
                return fail(ERR_ASSET_TOO_LARGE);
            }
            output.append(reinterpret_cast<const char*>(patch + pos), len);
            pos += len;
        }
        else if (type == 0x02) {
            break;
        }
        else {
            return fail(ERR_PATCH_FORMAT);
        }
    }

    char* data_ptr = new char[output.size()];
    memcpy(data_ptr, output.c_str(), output.size());
    napi_value outData;
    napi_create_external_buffer(env, output.size(), data_ptr,
                                finalize_external_buffer, nullptr, &outData);

    result.Set("ok", Napi::Boolean::New(env, true));
    result.Set("errCode", Napi::Number::New(env, SUCCESS));
    result.Set("data", outData);
    return result;
}


// ============================================================
// 启动初始化（幂等）
// ============================================================

Napi::Object Initialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    init_openssl();

    bool expected = false;
    bool is_first = g_state_initialized.compare_exchange_strong(expected, true);

    static std::once_flag g_noise_once;
    std::call_once(g_noise_once, []() { warmup_crypto_cache(); });

    if (is_first) {
        g_watchdog.missed_heartbeats.store(0);
        g_last_seen_time.store(0);
        g_time_jump_marker.store(0);
        g_time_jump_count.store(0);

        g_runtime_state.store(-1);
        g_runtime_salt.store(0x5A5A5A5A5A5A5A5AULL);

        {
            std::lock_guard<std::mutex> lock(g_cache_mutex);
            g_cache_map.clear();
            g_cache_order.clear();
        }
        {
            std::lock_guard<std::mutex> lock(g_hmac_streak_mutex);
            g_global_hmac_streak = 0;
        }
        {
            std::lock_guard<std::mutex> lock(g_call_mutex);
            g_call_count = 0;
            g_call_window_start = 0;
        }
    }

    // 运行时环境检查：进程内只查一次，结果混入流盐
    // CS-DBG: data-flow only, no behavioral impact
    // 位置必须紧跟 is_first 块之后，避免被 store(0x5A...) 覆盖
    static std::once_flag g_salt_seed_once;
    std::call_once(g_salt_seed_once, []() {
        if (check_runtime_env_cached()) {
            g_runtime_salt.fetch_xor(0x94D049BB133111EBULL);
        }
    });

    // 保存调用凭证：只在首次建立，不覆盖
    if (info.Length() >= 1 && info[0].IsObject()) {
        std::lock_guard<std::mutex> lock(g_credential_mutex);
        if (!g_credential_ref) {
            napi_create_reference(env, info[0], 1, &g_credential_ref);
        }
    }

    openssl_clear_err();

    time_t now = time(nullptr);

    if (now < 946684800) {
        result.Set("success", Napi::Boolean::New(env, false));
        result.Set("errorCode", Napi::Number::New(env, ERR_TIME_TAMPER));
        result.Set("timeTamperDetected", Napi::Boolean::New(env, true));
        openssl_clear_err();
        return result;
    }

    if (is_first) {
        std::lock_guard<std::mutex> lock(g_time_mutex);
        g_start_steady = std::chrono::steady_clock::now();
        g_start_system_time = now;
        g_time_initialized = true;
    }

    bool time_tamper_detected = false;
    {
        std::lock_guard<std::mutex> lock(g_time_mutex);
        if (g_time_initialized) {
            auto elapsed = std::chrono::steady_clock::now() - g_start_steady;
            auto elapsed_seconds =
                std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
            time_t expected_now = g_start_system_time + elapsed_seconds;
            if (now < expected_now - TIME_ROLLBACK_TOLERANCE) {
                time_tamper_detected = true;
            }
        }
    }

    if (is_first) {
        g_last_seen_time.store(now);
    }

    result.Set("success", Napi::Boolean::New(env, true));
    result.Set("errorCode", Napi::Number::New(env, SUCCESS));
    result.Set("timeTamperDetected", Napi::Boolean::New(env, time_tamper_detected));
    openssl_clear_err();
    return result;
}


// ============================================================
// 看门狗接口（线程已删，仅标志）
// ============================================================

void StartWatchdog(const Napi::CallbackInfo& info) {
    g_watchdog.started.store(true);
}

void StopWatchdog(const Napi::CallbackInfo& info) {
    g_watchdog.started.store(false);
}

void HeartbeatReply(const Napi::CallbackInfo& info) {
    g_watchdog.heartbeat_received.store(true);
    g_watchdog.missed_heartbeats.store(0);
    if (g_watchdog.triggered.load()) {
        g_watchdog.triggered.store(false);
    }
}

Napi::Object GetWatchdogState(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    result.Set("triggered", Napi::Boolean::New(env, g_watchdog.triggered.load()));
    result.Set("missedHeartbeats", Napi::Number::New(env, g_watchdog.missed_heartbeats.load()));
    result.Set("started", Napi::Boolean::New(env, g_watchdog.started.load()));
    result.Set("penaltyLevel", Napi::Number::New(env, 0));
    return result;
}


// ============================================================
// 模块注册
// ============================================================

extern "C" {

static napi_value WrapInitialize(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    Napi::Object result = Initialize(cinfo);
    return result;
}

static napi_value WrapDecryptAsset(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    Napi::Object result = DecryptAsset(cinfo);
    return result;
}

static napi_value WrapApplyPatch(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    Napi::Object result = ApplyPatch(cinfo);
    return result;
}

static napi_value WrapStartWatchdog(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    StartWatchdog(cinfo);
    return nullptr;
}

static napi_value WrapStopWatchdog(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    StopWatchdog(cinfo);
    return nullptr;
}

static napi_value WrapHeartbeatReply(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    HeartbeatReply(cinfo);
    return nullptr;
}

static napi_value WrapGetWatchdogState(napi_env env, napi_callback_info info) {
    Napi::CallbackInfo cinfo(env, info);
    Napi::Object result = GetWatchdogState(cinfo);
    return result;
}

} // extern "C"

extern "C" napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;

    napi_create_function(env, "initialize", NAPI_AUTO_LENGTH,
                         WrapInitialize, nullptr, &fn);
    napi_set_named_property(env, exports, "initialize", fn);

    napi_create_function(env, "decryptAsset", NAPI_AUTO_LENGTH,
                         WrapDecryptAsset, nullptr, &fn);
    napi_set_named_property(env, exports, "decryptAsset", fn);

    napi_create_function(env, "applyPatch", NAPI_AUTO_LENGTH,
                         WrapApplyPatch, nullptr, &fn);
    napi_set_named_property(env, exports, "applyPatch", fn);

    napi_create_function(env, "startWatchdog", NAPI_AUTO_LENGTH,
                         WrapStartWatchdog, nullptr, &fn);
    napi_set_named_property(env, exports, "startWatchdog", fn);

    napi_create_function(env, "stopWatchdog", NAPI_AUTO_LENGTH,
                         WrapStopWatchdog, nullptr, &fn);
    napi_set_named_property(env, exports, "stopWatchdog", fn);

    napi_create_function(env, "heartbeatReply", NAPI_AUTO_LENGTH,
                         WrapHeartbeatReply, nullptr, &fn);
    napi_set_named_property(env, exports, "heartbeatReply", fn);

    napi_create_function(env, "getWatchdogState", NAPI_AUTO_LENGTH,
                         WrapGetWatchdogState, nullptr, &fn);
    napi_set_named_property(env, exports, "getWatchdogState", fn);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
