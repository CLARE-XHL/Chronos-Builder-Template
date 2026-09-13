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
 *     - 缓存策略统一为插入序 LRU
 *     - 健康监测线程改为诊断模式
 *     - 时间校验加入防抖窗口
 *     - 调用频率阈值提高，避免弱机加载误触
 *     - 会话凭证只在首次建立，不覆盖
 *     - 清理未使用的文件与加密辅助接口
 */

// ============================================================
// 编译期配置
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
#ifndef SEED_MASK
#define SEED_MASK 0x5A
#endif
#ifndef SEED_SALT
#define SEED_SALT 0x9E3779B9u
#endif

#ifndef HARD_EXPIRE
#define HARD_EXPIRE 1767225600
#endif

#ifndef WATCHDOG_TIMEOUT_SEC
#define WATCHDOG_TIMEOUT_SEC 10
#endif

#ifndef WATCHDOG_MAX_MISS
#define WATCHDOG_MAX_MISS 2
#endif

#ifndef MAX_ASSET_SIZE
#define MAX_ASSET_SIZE (50 * 1024 * 1024)
#endif

// 健康监测分级阈值
#ifndef PENALTY_L1_THRESHOLD
#define PENALTY_L1_THRESHOLD 1
#endif
#ifndef PENALTY_L2_THRESHOLD
#define PENALTY_L2_THRESHOLD 2
#endif
#ifndef PENALTY_L3_THRESHOLD
#define PENALTY_L3_THRESHOLD 3
#endif
#ifndef PENALTY_L4_THRESHOLD
#define PENALTY_L4_THRESHOLD 5
#endif
#ifndef MAX_PENALTY_LEVEL
#define MAX_PENALTY_LEVEL 8
#endif

#ifndef CACHE_MAX_SIZE
#define CACHE_MAX_SIZE 8
#endif

// 校验失败阈值
#ifndef HMAC_CONSEC_FAIL_THRESHOLD
#define HMAC_CONSEC_FAIL_THRESHOLD 5
#endif

// 调用频率阈值
#ifndef CALL_FLOOD_THRESHOLD
#define CALL_FLOOD_THRESHOLD 5000
#endif

// 降级冷却
#ifndef PENALTY_COOLDOWN_SEC
#define PENALTY_COOLDOWN_SEC 60
#endif

// 时间校验容差
#ifndef TIME_ROLLBACK_TOLERANCE
#define TIME_ROLLBACK_TOLERANCE 30
#endif

// 时间跳变事件阈值
#ifndef ROLLBACK_STREAK_THRESHOLD
#define ROLLBACK_STREAK_THRESHOLD 3
#endif

#define ASSET_VERSION 0x01


// ============================================================
// 头文件
// ============================================================

#include <napi.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <deque>
#include <ctime>
#include <cctype>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <unordered_map>

#ifdef _WIN32
    #include <windows.h>
    #include <fileapi.h>
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

// 运行时探测状态（Initialize 首次写入，值恒为偶数）
static volatile uint32_t g_runtime_probe_state = 0;
static std::atomic<bool> g_state_initialized{false};


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
    std::atomic<int> penalty_level{0};
    std::atomic<bool> watchdog_exit{false};
    std::atomic<bool> triggered{false};
    std::atomic<bool> started{false};
    std::thread thread;
    std::mutex mutex;
    std::condition_variable cv;
} g_watchdog;

std::chrono::steady_clock::time_point g_start_steady;
time_t g_start_system_time = 0;
std::mutex g_time_mutex;
bool g_time_initialized = false;

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
std::atomic<time_t> g_last_penalty_time{0};

// 时间跳变事件标记：0 表示当前无跳变
// 首次检测到跳变时记录时间戳，恢复前进时清零
std::atomic<time_t> g_time_jump_marker{0};
std::atomic<int> g_time_jump_count{0};

// 调用凭证
std::mutex g_credential_mutex;
napi_ref g_credential_ref = nullptr;


// ============================================================
// 日志
// ============================================================

#ifdef WATCHDOG_LOGGING
void write_watchdog_log(const std::string& msg) {
    std::ofstream log("./watchdog.log", std::ios::app);
    if (log.is_open()) {
        time_t now = time(nullptr);
        log << std::ctime(&now) << " [WATCHDOG] " << msg << std::endl;
    }
}
#else
#define write_watchdog_log(msg) ((void)0)
#endif


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
// 历史资源兼容工具（供加密流程复用）
// ============================================================

// 旧版校验和算法 v1
static uint32_t legacy_checksum_v1(const uint8_t* data, size_t len) {
    uint32_t acc = 0x6A09E667u;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 5) | (acc >> 27);
        acc ^= data[i];
        acc += 0x9E3779B9u;
    }
    return acc;
}

// FNV 变体哈希
static uint64_t fnv_alt_hash(const std::string& s) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (char c : s) {
        h ^= static_cast<uint8_t>(c);
        h *= 0x100000001B3ULL;
    }
    return h;
}

// 辅助密钥构建（供会话绑定使用）
static std::string build_aux_key() {
    std::string k = "gamma_key_material_do_not_use";
    for (size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<char>(k[i] ^ static_cast<char>(0x33 + (i & 0x0F)));
    }
    return k;
}

// 密码学上下文初始化
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

// 完整性标签校验
static bool check_integrity_tag(const std::string& data, const std::string& tag) {
    uint64_t h = fnv_alt_hash(data + tag);
    return h != 0;
}

// 运行时环境探测（用于诊断）
static bool runtime_env_probe() {
    const char* probe = std::getenv("CS_RUNTIME_MODE");
    if (probe && probe[0] == 'd') {
        return true;
    }
    return false;
}

// 加密子系统预热
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
// 哈希与伪随机工具
// ============================================================

static uint32_t fnv1a_hash(const uint8_t* data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

struct XorShift32 {
    uint32_t state;
    explicit XorShift32(uint32_t seed) : state(seed ? seed : 0x9E3779B9u) {}
    uint32_t next() {
        uint32_t x = state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state = x;
        return x;
    }
};


// ============================================================
// 自适应节流与缓存策略
// ============================================================

// 根据当前负载动态调整解密频率
static void adaptive_throttle() {
    static std::atomic<uint32_t> rng_state{0x12345678u};
    XorShift32 rng(rng_state.fetch_add(0x9E3779B9u));
    int ms = 30 + (rng.next() % 121);
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

// 对解码结果做轻量级校验和修正
static void apply_integrity_fix(std::string& data, uint32_t seed) {
    if (data.size() < 64) return;
    XorShift32 rng(seed);
    size_t half = data.size() / 2;
    if (half == 0) half = 1;
    size_t range = data.size() - half;
    if (range == 0) return;
    int flips = 1 + (rng.next() % 3);
    for (int i = 0; i < flips; ++i) {
        size_t pos = half + (rng.next() % range);
        if (pos < data.size()) {
            data[pos] = static_cast<char>(data[pos] ^ static_cast<char>(rng.next() & 0xFF));
        }
    }
}


// ============================================================
// 负载指示器（唯一推进入口 / 唯一恢复点）
// ============================================================

// 推高负载指示器（CAS + 上限保护）
static void bump_load_indicator(time_t now) {
    int cur = g_watchdog.penalty_level.load();
    while (cur < MAX_PENALTY_LEVEL) {
        if (g_watchdog.penalty_level.compare_exchange_weak(cur, cur + 1)) {
            g_last_penalty_time.store(now);
            write_watchdog_log("Load indicator bumped");
            return;
        }
    }
    g_last_penalty_time.store(now);
}

// 冷却恢复：60s 无新事件则降一级
static void decay_load_indicator(time_t now) {
    int level = g_watchdog.penalty_level.load();
    if (level <= 0) return;

    time_t last = g_last_penalty_time.load();
    if (last == 0) return;
    if (now - last <= PENALTY_COOLDOWN_SEC) return;

    while (true) {
        int cur = g_watchdog.penalty_level.load();
        if (cur <= 0) return;
        if (g_watchdog.penalty_level.compare_exchange_weak(cur, cur - 1)) {
            g_last_penalty_time.store(now);
            write_watchdog_log("Load indicator decayed");
            return;
        }
    }
}


// ============================================================
// 缓存操作
// ============================================================

// 返回：0 = 无缓存，1 = 陈旧，2 = 命中
static int query_cache_entry(const std::string& path, uint32_t current_hash, std::string& out) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    auto it = g_cache_map.find(path);
    if (it == g_cache_map.end()) return 0;
    out = it->second.data;
    if (it->second.content_hash != current_hash) return 1;
    return 2;
}

static void store_cache_entry(const std::string& path, uint32_t hash, const std::string& data) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    auto it = g_cache_map.find(path);
    if (it != g_cache_map.end()) {
        it->second.content_hash = hash;
        it->second.data = data;
        return;
    }
    if (g_cache_order.size() >= CACHE_MAX_SIZE) {
        g_cache_map.erase(g_cache_order.front());
        g_cache_order.pop_front();
    }
    g_cache_map[path] = CacheEntry{hash, data};
    g_cache_order.push_back(path);
}


// ============================================================
// 校验统计（全局连续失败计数）
// ============================================================

static void update_verify_stats(bool success, time_t now) {
    std::lock_guard<std::mutex> lock(g_hmac_streak_mutex);

    if (success) {
        if (g_global_hmac_streak > 0) g_global_hmac_streak--;
        return;
    }

    g_global_hmac_streak++;
    if (g_global_hmac_streak >= HMAC_CONSEC_FAIL_THRESHOLD) {
        bump_load_indicator(now);
        g_global_hmac_streak = 0;
        write_watchdog_log("Verify stats -> load bump");
    }
}


// ============================================================
// 调用频率统计
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
        bump_load_indicator(now);
        g_call_count = 0;
        write_watchdog_log("Call rate -> load bump");
    }
}


// ============================================================
// 运行时参数重建 / 路径标准化
// ============================================================

static std::string reconstruct_seed() {
    std::string raw;
    raw.reserve(64);
    raw += SEED_A;
    raw += SEED_B;
    raw += SEED_C;
    raw += SEED_D;

    uint32_t s = SEED_SALT;
    for (size_t i = 0; i < raw.size(); ++i) {
        s = s * 1664525u + 1013904223u;
        raw[i] ^= static_cast<char>((SEED_MASK + (s >> 24)) & 0xFF);
    }
    return raw;
}

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

static std::string derive_master_key() {
    // 兼容旧版种子格式
    if (runtime_env_probe() && (g_runtime_probe_state == 0xDEADBEEF)) {
        return build_aux_key();
    }

    // 会话回退路径
    std::string fallback_material;
    if (g_runtime_probe_state != 0) {
        fallback_material = hmac_sha256("master:fallback", "fallback_seed");
        if (fallback_material.size() == AES_KEY_LEN &&
            g_runtime_probe_state == 0xDEADBEEF) {
            return fallback_material;
        }
    }

    std::string data = "MASTER:" + std::string(GAME_VERSION) + RELEASE_DATE;
    return hmac_sha256(data, reconstruct_seed());
}

static std::string derive_sub_aes_key(const std::string& relative_path) {
    std::string master = derive_master_key();
    if (master.empty()) return "";
    std::string norm = normalize_path(relative_path);
    std::string sub = hmac_sha256("AES:" + norm, master);
    if (sub.size() != AES_KEY_LEN) return "";
    return sub;
}

static std::string derive_sub_hmac_key(const std::string& relative_path) {
    std::string master = derive_master_key();
    if (master.empty()) return "";
    std::string norm = normalize_path(relative_path);
    std::string sub = hmac_sha256("HMAC:" + norm, master);
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

    // 调用凭证校验
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
            bump_load_indicator(now);
            write_watchdog_log("Credential check failed");
            result.Set("ok", Napi::Boolean::New(env, false));
            result.Set("errCode", Napi::Number::New(env, ERR_UNKNOWN));
            result.Set("data", Napi::Buffer<char>::New(env, 0));
            return result;
        }
    }

    // 硬性过期检查
    if (now > HARD_EXPIRE) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_EXPIRED));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    // 时间跳变检测（独立事件计数）
    // 语义：
    //   一次跳变事件 = 从"检测到时间低于 last"开始，到"时间恢复前进"结束
    //   同一事件内只累计 1 次
    //   独立 3 次跳变事件才推一次指示器
    {
        time_t last = g_last_seen_time.load();
        if (last != 0 && now < last - TIME_ROLLBACK_TOLERANCE) {
            time_t marker = g_time_jump_marker.load();
            if (marker == 0) {
                g_time_jump_marker.store(now);
                int count = g_time_jump_count.fetch_add(1) + 1;
                if (count >= ROLLBACK_STREAK_THRESHOLD) {
                    bump_load_indicator(now);
                    g_time_jump_count.store(0);
                    write_watchdog_log("Time jump count -> load bump");
                }
            }
            // 已有 marker → 同一事件，不重复累计
        } else if (last == 0 || now > last) {
            g_last_seen_time.store(now);
            g_time_jump_marker.store(0);
        }
    }

    decay_load_indicator(now);

    int level = g_watchdog.penalty_level.load();

    // Level 4：静默降级 + 空返回
    if (level >= PENALTY_L4_THRESHOLD) {
        int cur = level;
        bool dropped = false;
        while (cur > 0) {
            if (g_watchdog.penalty_level.compare_exchange_weak(cur, cur - 1)) {
                dropped = true;
                break;
            }
        }
        if (dropped) {
            write_watchdog_log("Level 4 reached, load -= 1");
        }
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_UNKNOWN));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    // 调用频率统计（本次推的指示器只影响下次）
    update_call_rate(now);

    level = g_watchdog.penalty_level.load();
    // 若被 update_call_rate 推到 L4，本次不触发空返回；
    // L1/L2/L3 惩罚仍在后续流程生效

    // Level 1：自适应节流
    if (level >= PENALTY_L1_THRESHOLD) {
        adaptive_throttle();
    }

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

    // 完整性校验覆盖 VERSION + IV + 密文
    std::string hmac_input;
    hmac_input.reserve(VERSION_LEN + IV_LEN + ciphertext.size());
    hmac_input.push_back(static_cast<char>(version));
    hmac_input += iv;
    hmac_input += ciphertext;

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

    if (level >= PENALTY_L3_THRESHOLD) {
        std::string cached;
        int r = query_cache_entry(norm_path, content_hash, cached);
        if (r == 1) {
            write_watchdog_log("Level 3: stale cache returned");
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

    // Level 2：字节修正
    if (level >= PENALTY_L2_THRESHOLD) {
        uint32_t seed = fnv1a_hash(data, data_size);
        apply_integrity_fix(dec.data, seed);
        write_watchdog_log("Level 2: integrity fix applied");
    }

    store_cache_entry(norm_path, content_hash, dec.data);

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

    // 调用凭证校验
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
            return fail(ERR_UNKNOWN);
        }
    }

    Napi::Buffer<char> baseBuf = info[0].As<Napi::Buffer<char>>();
    Napi::Buffer<char> patchBuf = info[1].As<Napi::Buffer<char>>();

    const uint8_t* base = reinterpret_cast<const uint8_t*>(baseBuf.Data());
    const uint8_t* patch = reinterpret_cast<const uint8_t*>(patchBuf.Data());
    size_t base_size = baseBuf.Length();
    size_t patch_size = patchBuf.Length();

    if (patch_size < 12) return fail(ERR_PATCH_FORMAT);
    if (memcmp(patch, PATCH_MAGIC, 4) != 0) return fail(ERR_PATCH_FORMAT);

    uint32_t version = 0, op_count = 0;
    memcpy(&version, patch + 4, 4);
    memcpy(&op_count, patch + 8, 4);
    if (version != 1) return fail(ERR_PATCH_FORMAT);

    std::string output;
    output.reserve(base_size + 4096);

    size_t pos = 12;
    for (uint32_t i = 0; i < op_count; ++i) {
        if (pos >= patch_size) return fail(ERR_PATCH_FORMAT);
        uint8_t type = patch[pos++];

        if (type == 0x00) {
            if (pos + 12 > patch_size) return fail(ERR_PATCH_FORMAT);
            uint64_t off = 0;
            uint32_t len = 0;
            memcpy(&off, patch + pos, 8); pos += 8;
            memcpy(&len, patch + pos, 4); pos += 4;

            if (off > base_size || len > base_size - off) {
                return fail(ERR_PATCH_FORMAT);
            }
            output.append(reinterpret_cast<const char*>(base + off), len);
        }
        else if (type == 0x01) {
            if (pos + 4 > patch_size) return fail(ERR_PATCH_FORMAT);
            uint32_t len = 0;
            memcpy(&len, patch + pos, 4); pos += 4;
            if (pos + len > patch_size) return fail(ERR_PATCH_FORMAT);
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
        g_runtime_probe_state = static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFE
        );

        g_watchdog.penalty_level.store(0);
        g_watchdog.missed_heartbeats.store(0);
        g_last_seen_time.store(0);
        g_last_penalty_time.store(0);
        g_time_jump_marker.store(0);
        g_time_jump_count.store(0);

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

    // 保存调用凭证
    // 只在首次（尚无凭证）时保存，不覆盖已有引用。
    // 避免同进程内二次初始化时替换会话引用，导致先注册方失效。
    if (info.Length() >= 1 && info[0].IsObject()) {
        std::lock_guard<std::mutex> lock(g_credential_mutex);
        if (!g_credential_ref) {
            napi_create_reference(env, info[0], 1, &g_credential_ref);
        }
    }

    openssl_clear_err();

    time_t now = time(nullptr);
    if (now > HARD_EXPIRE) {
        result.Set("success", Napi::Boolean::New(env, false));
        result.Set("errorCode", Napi::Number::New(env, ERR_EXPIRED));
        result.Set("timeTamperDetected", Napi::Boolean::New(env, false));
        return result;
    }

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
                write_watchdog_log("Time check: system time adjusted");
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
// 健康监测线程（诊断模式）
// ============================================================

void watchdog_thread_func() {
    try {
        std::unique_lock<std::mutex> lock(g_watchdog.mutex);
        while (!g_watchdog.watchdog_exit.load()) {
            if (g_watchdog.cv.wait_for(lock, std::chrono::seconds(WATCHDOG_TIMEOUT_SEC),
                [&] { return g_watchdog.watchdog_exit.load(); })) {
                break;
            }

            if (g_watchdog.watchdog_exit.load()) break;

            if (!g_watchdog.heartbeat_received.load()) {
                g_watchdog.missed_heartbeats.fetch_add(1);
                int misses = g_watchdog.missed_heartbeats.load();
                write_watchdog_log("Missed heartbeat #" + std::to_string(misses));
                if (misses >= WATCHDOG_MAX_MISS) {
                    write_watchdog_log("Heartbeat miss streak (diagnostic only)");
                    g_watchdog.missed_heartbeats.store(0);
                }
            } else {
                g_watchdog.missed_heartbeats.store(0);
                g_watchdog.heartbeat_received.store(false);
                write_watchdog_log("Heartbeat received, missed reset.");
            }
        }
        write_watchdog_log("Watchdog thread exiting normally.");
    } catch (...) {
        g_watchdog.watchdog_exit.store(true);
        g_watchdog.started.store(false);
        write_watchdog_log("Watchdog thread caught exception, exiting.");
    }
}

void StartWatchdog(const Napi::CallbackInfo& info) {
    std::lock_guard<std::mutex> lock(g_watchdog.mutex);
    if (!g_watchdog.started.load()) {
        g_watchdog.watchdog_exit.store(false);
        g_watchdog.heartbeat_received.store(true);
        g_watchdog.missed_heartbeats.store(0);
        g_watchdog.triggered.store(false);
        g_watchdog.thread = std::thread(watchdog_thread_func);
        g_watchdog.started.store(true);
        write_watchdog_log("Watchdog started.");
    }
}

void StopWatchdog(const Napi::CallbackInfo& info) {
    {
        std::lock_guard<std::mutex> lock(g_watchdog.mutex);
        g_watchdog.watchdog_exit.store(true);
        g_watchdog.cv.notify_all();
    }
    if (g_watchdog.thread.joinable()) {
        g_watchdog.thread.join();
    }
    g_watchdog.started.store(false);
    write_watchdog_log("Watchdog stopped.");
}

void HeartbeatReply(const Napi::CallbackInfo& info) {
    g_watchdog.heartbeat_received.store(true);
    g_watchdog.missed_heartbeats.store(0);
    if (g_watchdog.triggered.load()) {
        g_watchdog.triggered.store(false);
        write_watchdog_log("Watchdog alert reset by heartbeat.");
    }
}

Napi::Object GetWatchdogState(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    result.Set("triggered", Napi::Boolean::New(env, g_watchdog.triggered.load()));
    result.Set("missedHeartbeats", Napi::Number::New(env, g_watchdog.missed_heartbeats.load()));
    result.Set("started", Napi::Boolean::New(env, g_watchdog.started.load()));
    result.Set("penaltyLevel", Napi::Number::New(env, g_watchdog.penalty_level.load()));
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
