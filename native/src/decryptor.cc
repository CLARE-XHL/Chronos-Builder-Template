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

struct DecryptResult {
    bool ok;
    std::string data;
    int errCode;
};

static void openssl_clear_err() {
    while (ERR_get_error() != 0) {}
}

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

    result.ok = true;
    result.data = plaintext;
    result.errCode = SUCCESS;
    return result;
}


// ============================================================
// 看门狗守护线程
// ============================================================

// 看门狗线程函数（定义在 start_watchdog_internal 之前）
void watchdog_thread_func() {
    while (!g_watchdog.watchdog_exit.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(WATCHDOG_TIMEOUT_SEC));

        if (g_watchdog.watchdog_exit.load()) break;

        if (!g_watchdog.heartbeat_received.load()) {
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

static void start_watchdog_internal() {
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

static void stop_watchdog_internal() {
    g_watchdog.watchdog_exit.store(true);
    g_watchdog.started.store(false);
    write_watchdog_log("Watchdog stop signal sent.");
}

static void heartbeat_reply_internal() {
    g_watchdog.heartbeat_received.store(true);
    g_watchdog.missed_heartbeats.store(0);
    if (g_watchdog.triggered.load()) {
        g_watchdog.triggered.store(false);
        write_watchdog_log("Watchdog alert reset by heartbeat.");
    }
}

static napi_value get_watchdog_state_internal(napi_env env) {
    napi_value result;
    napi_create_object(env, &result);

    napi_value triggered, missedHeartbeats, started;
    napi_get_boolean(env, g_watchdog.triggered.load(), &triggered);
    napi_create_int32(env, g_watchdog.missed_heartbeats.load(), &missedHeartbeats);
    napi_get_boolean(env, g_watchdog.started.load(), &started);

    napi_set_named_property(env, result, "triggered", triggered);
    napi_set_named_property(env, result, "missedHeartbeats", missedHeartbeats);
    napi_set_named_property(env, result, "started", started);

    return result;
}


// ============================================================
// 纯 C N-API 导出函数（避免 Napi::CallbackInfo）
// ============================================================

static napi_value c_Initialize(napi_env env, napi_callback_info info) {
    // 初始化 OpenSSL
    init_openssl();

    // 初始化时钟
    {
        std::lock_guard<std::mutex> lock(g_time_mutex);
        if (!g_time_initialized) {
            g_start_steady = std::chrono::steady_clock::now();
            g_start_system_time = time(nullptr);
            g_time_initialized = true;
        }
    }

    time_t now = time(nullptr);
    napi_value result;
    napi_create_object(env, &result);

    // 检查硬过期
    if (now > HARD_EXPIRE) {
        napi_value success, errorCode, timeTamperDetected;
        napi_get_boolean(env, false, &success);
        napi_create_int32(env, ERR_EXPIRED, &errorCode);
        napi_get_boolean(env, false, &timeTamperDetected);
        napi_set_named_property(env, result, "success", success);
        napi_set_named_property(env, result, "errorCode", errorCode);
        napi_set_named_property(env, result, "timeTamperDetected", timeTamperDetected);
        return result;
    }

    // 检测时间回拨
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

    napi_value success, errorCode, timeTamperDetected;
    napi_get_boolean(env, true, &success);
    napi_create_int32(env, SUCCESS, &errorCode);
    napi_get_boolean(env, time_tamper_detected, &timeTamperDetected);
    napi_set_named_property(env, result, "success", success);
    napi_set_named_property(env, result, "errorCode", errorCode);
    napi_set_named_property(env, result, "timeTamperDetected", timeTamperDetected);

    return result;
}

static napi_value c_DecryptAsset(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    napi_value result;
    napi_create_object(env, &result);

    // 检查参数
    if (argc < 1) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_INVALID_FORMAT, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    bool is_buffer = false;
    napi_is_buffer(env, argv[0], &is_buffer);
    if (!is_buffer) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_INVALID_FORMAT, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    // 获取 Buffer 数据
    void* buffer_data = nullptr;
    size_t data_size = 0;
    napi_get_buffer_info(env, argv[0], &buffer_data, &data_size);

    if (data_size < ASSET_HEADER_LEN) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_INVALID_FORMAT, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    if (data_size > MAX_ASSET_SIZE) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_ASSET_TOO_LARGE, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    const uint8_t* input_data = reinterpret_cast<const uint8_t*>(buffer_data);

    // 验证魔数
    if (!constant_time_equals(input_data, MAGIC_BYTES, MAGIC_LEN)) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_INVALID_FORMAT, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    std::string iv(reinterpret_cast<const char*>(input_data + MAGIC_LEN), IV_LEN);
    std::string stored_hmac(reinterpret_cast<const char*>(input_data + MAGIC_LEN + IV_LEN), HMAC_LEN);
    std::string ciphertext(
        reinterpret_cast<const char*>(input_data + ASSET_HEADER_LEN),
        data_size - ASSET_HEADER_LEN);

    std::string aes_key = derive_aes_key();
    std::string hmac_key = derive_hmac_key();

    if (aes_key.empty() || hmac_key.empty()) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_UNKNOWN, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    std::string computed_hmac = hmac_sha256(ciphertext, hmac_key);
    if (computed_hmac.size() != HMAC_LEN ||
        !constant_time_equals(
            reinterpret_cast<const uint8_t*>(computed_hmac.data()),
            reinterpret_cast<const uint8_t*>(stored_hmac.data()),
            HMAC_LEN)) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, ERR_DECRYPT_HMAC, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    DecryptResult dec = aes_decrypt(ciphertext,
        reinterpret_cast<const unsigned char*>(aes_key.c_str()), iv);

    if (!dec.ok) {
        napi_value ok, errCode, data;
        napi_get_boolean(env, false, &ok);
        napi_create_int32(env, dec.errCode, &errCode);
        napi_create_buffer(env, 0, nullptr, &data);
        napi_set_named_property(env, result, "ok", ok);
        napi_set_named_property(env, result, "errCode", errCode);
        napi_set_named_property(env, result, "data", data);
        return result;
    }

    napi_value ok, errCode, outData;
    napi_get_boolean(env, true, &ok);
    napi_create_int32(env, SUCCESS, &errCode);
    napi_create_buffer_copy(env, dec.data.size(), dec.data.c_str(), nullptr, &outData);
    napi_set_named_property(env, result, "ok", ok);
    napi_set_named_property(env, result, "errCode", errCode);
    napi_set_named_property(env, result, "data", outData);

    return result;
}

static napi_value c_StartWatchdog(napi_env env, napi_callback_info info) {
    start_watchdog_internal();
    return nullptr;
}

static napi_value c_StopWatchdog(napi_env env, napi_callback_info info) {
    stop_watchdog_internal();
    return nullptr;
}

static napi_value c_HeartbeatReply(napi_env env, napi_callback_info info) {
    heartbeat_reply_internal();
    return nullptr;
}

static napi_value c_GetWatchdogState(napi_env env, napi_callback_info info) {
    return get_watchdog_state_internal(env);
}


// ============================================================
// Node-API 模块注册
// ============================================================

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;

    napi_create_function(env, "initialize", NAPI_AUTO_LENGTH,
                         c_Initialize, nullptr, &fn);
    napi_set_named_property(env, exports, "initialize", fn);

    napi_create_function(env, "decryptAsset", NAPI_AUTO_LENGTH,
                         c_DecryptAsset, nullptr, &fn);
    napi_set_named_property(env, exports, "decryptAsset", fn);

    napi_create_function(env, "startWatchdog", NAPI_AUTO_LENGTH,
                         c_StartWatchdog, nullptr, &fn);
    napi_set_named_property(env, exports, "startWatchdog", fn);

    napi_create_function(env, "stopWatchdog", NAPI_AUTO_LENGTH,
                         c_StopWatchdog, nullptr, &fn);
    napi_set_named_property(env, exports, "stopWatchdog", fn);

    napi_create_function(env, "heartbeatReply", NAPI_AUTO_LENGTH,
                         c_HeartbeatReply, nullptr, &fn);
    napi_set_named_property(env, exports, "heartbeatReply", fn);

    napi_create_function(env, "getWatchdogState", NAPI_AUTO_LENGTH,
                         c_GetWatchdogState, nullptr, &fn);
    napi_set_named_property(env, exports, "getWatchdogState", fn);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
