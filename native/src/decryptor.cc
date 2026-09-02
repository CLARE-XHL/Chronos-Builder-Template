/**
 * ============================================================
 * Chronos Seal — Time as the seal, action as the key,
 * time itself guards originality.
 * This freedom is dedicated to every independent creator,
 * and to that visitor, Liberty, who has not set foot on the island
 * in a long time.
 * ============================================================
 *
 * Chronos Seal 2.1 - decryptor.cc
 * 适用于 RPG Maker MV / MZ (NW.js / Node.js)
 *
 * 编译依赖:
 *   - node-addon-api (N-API)
 *   - OpenSSL 1.1.1+ (libssl, libcrypto)
 *
 * 编译命令 (GitHub Actions 云端执行):
 *   node-gyp configure
 *   node-gyp build --release
 *
 * 版本: 2.1
 * 日期: 2026-09-02
 *
 * 核心改进 (V2.1 素材解密版):
 *   - 移除检查点（checkpoint）全部逻辑
 *   - 新增素材解密接口（decryptAsset）
 *   - 密钥派生机制不变，但不再用于 system.json
 *   - system.json 不再加密，改为明文读取
 *   - 保留看门狗守护线程（改为状态上报模式）
 *   - 素材格式: [MAGIC(8) + IV(16) + HMAC(32) + AES密文]
 *   - AES密钥和HMAC密钥分离派生
 *   - 不再依赖 config.h，所有编译期常量由宏定义传入
 *   - 固定时间 HMAC 比较，防止计时攻击
 *
 * 设计哲学:
 *   - 密钥不存在任何文件中，由 C++ 运行时派生
 *   - 素材解密由 C++ 层统一接管
 *   - JS 层仅作为数据通道，不接触密钥
 */

// ============================================================
// 编译期常量（由 GitHub Actions 通过 -D 宏传入）
// ============================================================

#ifndef GAME_VERSION
#define GAME_VERSION "2.1.0"
#endif

#ifndef RELEASE_DATE
#define RELEASE_DATE "2026-09-02"
#endif

#ifndef DERIVATION_SEED
#define DERIVATION_SEED "REPLACE_ME_WITH_RANDOM_SEED_IN_ACTIONS"
#endif

#ifndef HARD_EXPIRE
#define HARD_EXPIRE 1767225600  // 2027-01-01
#endif

#ifndef WATCHDOG_TIMEOUT_SEC
#define WATCHDOG_TIMEOUT_SEC 10
#endif

#ifndef WATCHDOG_MAX_MISS
#define WATCHDOG_MAX_MISS 2
#endif


// ============================================================
// 头文件
// ============================================================

#include <napi.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <ctime>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <algorithm>

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


// ============================================================
// 编译开关
// ============================================================

// #define WATCHDOG_LOGGING  // Release 版请注释掉
// #define ENABLE_DEBUG_BASE64  // 调试用 Base64 函数（默认禁用）


// ============================================================
// 常量定义
// ============================================================

const size_t AES_KEY_LEN = 32;
const size_t HMAC_LEN = 32;
const size_t IV_LEN = 16;
const size_t MAGIC_LEN = 8;
const size_t ASSET_HEADER_LEN = MAGIC_LEN + IV_LEN + HMAC_LEN;  // 56 字节
const size_t MAX_ASSET_SIZE = 200 * 1024 * 1024;                // 200 MB

// FIX: 魔数常量（8 字节）
const uint8_t MAGIC_BYTES[MAGIC_LEN] = {'C', 'H', 'R', 'N', 'S', 'L', 'S', 'E'};


// ============================================================
// 错误码定义
// ============================================================

enum ErrorCode {
    SUCCESS = 0,
    ERR_EXPIRED = 10,
    ERR_SIGNATURE = 30,
    ERR_NO_RES = 40,
    ERR_UNKNOWN = -1,
    ERR_DECRYPT_PADDING = 60,
    ERR_DECRYPT_HMAC = 61,
    ERR_ASSET_TOO_LARGE = 62,
    ERR_INVALID_FORMAT = 63
};


// ============================================================
// 全局状态
// ============================================================

// 看门狗状态（不再直接 exit，由 JS 层处理）
struct WatchdogState {
    std::atomic<bool> heartbeat_received{false};
    std::atomic<int> missed_heartbeats{0};
    std::atomic<bool> watchdog_exit{false};
    std::atomic<bool> triggered{false};
    std::atomic<bool> started{false};
    std::thread thread;
    std::mutex mutex;
} g_watchdog;

// 单调时钟记录（检测系统时间回拨）
std::chrono::steady_clock::time_point g_start_steady;
time_t g_start_system_time = 0;
std::mutex g_time_mutex;
bool g_time_initialized = false;

// OpenSSL 初始化（只执行一次）
std::once_flag g_openssl_init_flag;


// ============================================================
// 日志辅助
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
// 固定时间 HMAC 比较（防计时攻击）—— FIX
// ============================================================

static bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}


// ============================================================
// Base64 编解码（仅调试构建）
// ============================================================

#ifdef ENABLE_DEBUG_BASE64

std::string base64_encode(const std::string& binary) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (char c : binary) {
        char_array_3[i++] = static_cast<unsigned char>(c);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; ++i) {
                result += b64[char_array_4[i]];
            }
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 3; ++j) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        for (int j = 0; j < i + 1; ++j) {
            result += b64[char_array_4[j]];
        }
        while (i++ < 3) result += '=';
    }
    return result;
}

std::string base64_decode(const std::string& encoded) {
    static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (char c : encoded) {
        if (c == '=') break;
        size_t pos = b64.find(c);
        if (pos == std::string::npos) {
            return "";
        }
        char_array_4[i++] = static_cast<unsigned char>(pos);
        if (i == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
            for (i = 0; i < 3; ++i) {
                result += static_cast<char>(char_array_3[i]);
            }
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 4; ++j) char_array_4[j] = 0;
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        for (int j = 0; j < i - 1; ++j) {
            result += static_cast<char>(char_array_3[j]);
        }
    }
    return result;
}

#endif // ENABLE_DEBUG_BASE64


// ============================================================
// HMAC-SHA256
// ============================================================

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
// OpenSSL 初始化（只执行一次）
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


// ============================================================
// V2.1：密钥派生函数（AES 和 HMAC 分离）
// ============================================================

// FIX: 密钥派生失败时返回空字符串，而非全零
std::string derive_aes_key() {
    std::string data = "AES:" + std::string(GAME_VERSION) + RELEASE_DATE;
    std::string key = hmac_sha256(data, DERIVATION_SEED);
    if (key.size() != AES_KEY_LEN) {
        return "";
    }
    return key;
}

std::string derive_hmac_key() {
    std::string data = "HMAC:" + std::string(GAME_VERSION) + RELEASE_DATE;
    std::string key = hmac_sha256(data, DERIVATION_SEED);
    if (key.size() != HMAC_LEN) {
        return "";
    }
    return key;
}


// ============================================================
// 文件操作
// ============================================================

std::string read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(content.c_str(), static_cast<std::streamsize>(content.size()));
    return file.good();
}

bool file_exists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}


// ============================================================
// AES-256-CBC 加解密
// ============================================================

std::string aes_encrypt(const std::string& plaintext, const unsigned char* key,
                        std::string& iv_out) {
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return "";
    iv_out = std::string(reinterpret_cast<char*>(iv), 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    int len = 0, total = 0;
    std::string ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), '\0');

    if (!EVP_EncryptUpdate(ctx,
                           reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                           reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                           static_cast<int>(plaintext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    total = len;

    if (!EVP_EncryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char*>(&ciphertext[total]), &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    total += len;
    ciphertext.resize(total);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

/**
 * AES 解密（返回错误码）
 * 返回: { ok: bool, data: string, errCode: int }
 */
struct DecryptResult {
    bool ok;
    std::string data;
    int errCode;
};

// FIX: OpenSSL 错误队列清空封装
static void openssl_clear_err() {
    while (ERR_get_error() != 0) {}
}

DecryptResult aes_decrypt(const std::string& ciphertext, const unsigned char* key,
                          const std::string& iv) {
    DecryptResult result{false, "", ERR_UNKNOWN};

    if (iv.size() != 16) {
        result.errCode = ERR_INVALID_FORMAT;
        openssl_clear_err();  // FIX
        return result;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.errCode = ERR_UNKNOWN;
        openssl_clear_err();  // FIX
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
        openssl_clear_err();  // FIX
        return result;
    }
    total = len;

    int final_len = 0;
    if (!EVP_DecryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char*>(&plaintext[total]), &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        result.errCode = ERR_DECRYPT_PADDING;
        openssl_clear_err();  // FIX
        return result;
    }
    total += final_len;
    plaintext.resize(total);

    EVP_CIPHER_CTX_free(ctx);

    result.ok = true;
    result.data = plaintext;
    result.errCode = SUCCESS;
    return result;
}


// ============================================================
// 素材解密接口（核心）
// ============================================================

/**
 * 解密素材文件
 * 存储格式: [MAGIC(8) + IV(16) + HMAC(32) + AES密文]
 * 解密流程: 1. 验证魔数 2. 提取 IV 和 HMAC 3. 验证 HMAC 4. AES 解密
 */
Napi::Object DecryptAsset(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

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

    // FIX: 验证魔数
    if (!constant_time_equals(data, MAGIC_BYTES, MAGIC_LEN)) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    // 提取 IV
    std::string iv(reinterpret_cast<const char*>(data + MAGIC_LEN), IV_LEN);

    // 提取 HMAC
    std::string stored_hmac(reinterpret_cast<const char*>(data + MAGIC_LEN + IV_LEN), HMAC_LEN);

    // 提取密文
    std::string ciphertext(
        reinterpret_cast<const char*>(data + ASSET_HEADER_LEN),
        data_size - ASSET_HEADER_LEN);

    // 派生密钥
    std::string aes_key = derive_aes_key();
    std::string hmac_key = derive_hmac_key();

    // FIX: 密钥为空时明确报错
    if (aes_key.empty() || hmac_key.empty()) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_UNKNOWN));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    // FIX: 固定时间 HMAC 比较
    std::string computed_hmac = hmac_sha256(ciphertext, hmac_key);
    if (computed_hmac.size() != HMAC_LEN ||
        !constant_time_equals(
            reinterpret_cast<const uint8_t*>(computed_hmac.data()),
            reinterpret_cast<const uint8_t*>(stored_hmac.data()),
            HMAC_LEN)) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_DECRYPT_HMAC));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    DecryptResult dec = aes_decrypt(ciphertext,
        reinterpret_cast<const unsigned char*>(aes_key.c_str()), iv);

    if (!dec.ok) {
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, dec.errCode));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    result.Set("ok", Napi::Boolean::New(env, true));
    result.Set("errCode", Napi::Number::New(env, SUCCESS));
    result.Set("data", Napi::Buffer<char>::Copy(env, dec.data.c_str(), dec.data.size()));
    return result;
}


// ============================================================
// 启动初始化
// ============================================================

Napi::Object Initialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    init_openssl();

    {
        std::lock_guard<std::mutex> lock(g_time_mutex);
        if (!g_time_initialized) {
            g_start_steady = std::chrono::steady_clock::now();
            g_start_system_time = time(nullptr);
            g_time_initialized = true;
        }
    }

    time_t now = time(nullptr);
    if (now > HARD_EXPIRE) {
        result.Set("success", Napi::Boolean::New(env, false));
        result.Set("errorCode", Napi::Number::New(env, ERR_EXPIRED));
        result.Set("timeTamperDetected", Napi::Boolean::New(env, false));
        return result;
    }

    bool time_tamper_detected = false;
    {
        std::lock_guard<std::mutex> lock(g_time_mutex);
        if (g_time_initialized) {
            auto elapsed = std::chrono::steady_clock::now() - g_start_steady;
            auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
            time_t expected_now = g_start_system_time + elapsed_seconds;
            if (now < expected_now - 5) {
                time_tamper_detected = true;
                write_watchdog_log("Time tamper detected: system time jumped backward");
            }
        }
    }

    result.Set("success", Napi::Boolean::New(env, true));
    result.Set("errorCode", Napi::Number::New(env, SUCCESS));
    result.Set("timeTamperDetected", Napi::Boolean::New(env, time_tamper_detected));
    return result;
}


// ============================================================
// 看门狗守护线程
// ============================================================

void watchdog_thread_func() {
    while (!g_watchdog.watchdog_exit.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(WATCHDOG_TIMEOUT_SEC));

        if (g_watchdog.watchdog_exit.load()) break;

        if (!g_watchdog.heartbeat_received.load()) {
            // FIX: 简化计数逻辑
            g_watchdog.missed_heartbeats.fetch_add(1);
            int misses = g_watchdog.missed_heartbeats.load();
            write_watchdog_log("Missed heartbeat #" + std::to_string(misses));
            if (misses >= WATCHDOG_MAX_MISS) {
                write_watchdog_log("Watchdog triggered! Sending alert flag.");
                g_watchdog.triggered.store(true);
            }
        } else {
            g_watchdog.missed_heartbeats.store(0);
            g_watchdog.heartbeat_received.store(false);
            write_watchdog_log("Heartbeat received, resetting counter.");
        }
    }
    write_watchdog_log("Watchdog thread exiting normally.");
}

void StartWatchdog(const Napi::CallbackInfo& info) {
    std::lock_guard<std::mutex> lock(g_watchdog.mutex);
    if (!g_watchdog.started.load()) {
        g_watchdog.watchdog_exit.store(false);
        g_watchdog.heartbeat_received.store(true);
        g_watchdog.missed_heartbeats.store(0);
        g_watchdog.triggered.store(false);
        g_watchdog.thread = std::thread(watchdog_thread_func);
        g_watchdog.thread.detach();
        g_watchdog.started.store(true);
        write_watchdog_log("Watchdog started.");
    }
}

void StopWatchdog(const Napi::CallbackInfo& info) {
    g_watchdog.watchdog_exit.store(true);
    g_watchdog.started.store(false);
    write_watchdog_log("Watchdog stop signal sent.");
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
    return result;
}


// ============================================================
// Node-API 模块注册
// ============================================================

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("initialize", Napi::Function::New(env, Initialize));
    exports.Set("decryptAsset", Napi::Function::New(env, DecryptAsset));
    exports.Set("startWatchdog", Napi::Function::New(env, StartWatchdog));
    exports.Set("stopWatchdog", Napi::Function::New(env, StopWatchdog));
    exports.Set("heartbeatReply", Napi::Function::New(env, HeartbeatReply));
    exports.Set("getWatchdogState", Napi::Function::New(env, GetWatchdogState));
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
