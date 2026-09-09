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

#ifndef MAX_ASSET_SIZE
#define MAX_ASSET_SIZE (50 * 1024 * 1024)
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
#include <condition_variable>
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

// #define WATCHDOG_LOGGING


// ============================================================
// 常量定义
// ============================================================

const size_t AES_KEY_LEN = 32;
const size_t HMAC_LEN = 32;
const size_t IV_LEN = 16;
const size_t MAGIC_LEN = 8;
const size_t ASSET_HEADER_LEN = MAGIC_LEN + IV_LEN + HMAC_LEN;

const uint8_t MAGIC_BYTES[MAGIC_LEN] = {'C', 'H', 'R', 'N', 'S', 'L', 'S', 'E'};


// ============================================================
// 错误码定义
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
    ERR_INVALID_FORMAT = 63
};


// ============================================================
// 全局状态
// ============================================================

struct WatchdogState {
    std::atomic<bool> heartbeat_received{false};
    std::atomic<int> missed_heartbeats{0};
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
// 固定时间 HMAC 比较
// ============================================================

static bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}


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
// V2.1：密钥派生函数
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
        openssl_clear_err();
        return "";
    }
    total = len;

    if (!EVP_EncryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char*>(&ciphertext[total]), &len)) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_clear_err();
        return "";
    }
    total += len;
    ciphertext.resize(total);

    EVP_CIPHER_CTX_free(ctx);
    openssl_clear_err();
    return ciphertext;
}

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
// 素材解密接口
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

    if (!constant_time_equals(data, MAGIC_BYTES, MAGIC_LEN)) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_INVALID_FORMAT));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    std::string iv(reinterpret_cast<const char*>(data + MAGIC_LEN), IV_LEN);
    std::string stored_hmac(reinterpret_cast<const char*>(data + MAGIC_LEN + IV_LEN), HMAC_LEN);
    std::string ciphertext(
        reinterpret_cast<const char*>(data + ASSET_HEADER_LEN),
        data_size - ASSET_HEADER_LEN);

    std::string aes_key = derive_aes_key();
    std::string hmac_key = derive_hmac_key();

    if (aes_key.empty() || hmac_key.empty()) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_UNKNOWN));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
    }

    std::string computed_hmac = hmac_sha256(ciphertext, hmac_key);
    if (computed_hmac.size() != HMAC_LEN ||
        !constant_time_equals(
            reinterpret_cast<const uint8_t*>(computed_hmac.data()),
            reinterpret_cast<const uint8_t*>(stored_hmac.data()),
            HMAC_LEN)) {
        openssl_clear_err();
        result.Set("ok", Napi::Boolean::New(env, false));
        result.Set("errCode", Napi::Number::New(env, ERR_DECRYPT_HMAC));
        result.Set("data", Napi::Buffer<char>::New(env, 0));
        return result;
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
// 启动初始化
// ============================================================

Napi::Object Initialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    init_openssl();
    openssl_clear_err();

    time_t now = time(nullptr);
    if (now > HARD_EXPIRE) {
        result.Set("success", Napi::Boolean::New(env, false));
        result.Set("errorCode", Napi::Number::New(env, ERR_EXPIRED));
        result.Set("timeTamperDetected", Napi::Boolean::New(env, false));
        return result;
    }

    if (now < 946684800 || now > 2208988800) {
        result.Set("success", Napi::Boolean::New(env, false));
        result.Set("errorCode", Napi::Number::New(env, ERR_TIME_TAMPER));
        result.Set("timeTamperDetected", Napi::Boolean::New(env, true));
        openssl_clear_err();
        return result;
    }

    {
        std::lock_guard<std::mutex> lock(g_time_mutex);
        if (!g_time_initialized) {
            g_start_steady = std::chrono::steady_clock::now();
            g_start_system_time = now;
            g_time_initialized = true;
        }
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
    openssl_clear_err();
    return result;
}


// ============================================================
// 看门狗
// ============================================================

void watchdog_thread_func() {
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
    return result;
}


// ============================================================
// 纯 C N-API 模块注册
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

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;

    napi_create_function(env, "initialize", NAPI_AUTO_LENGTH,
                         WrapInitialize, nullptr, &fn);
    napi_set_named_property(env, exports, "initialize", fn);

    napi_create_function(env, "decryptAsset", NAPI_AUTO_LENGTH,
                         WrapDecryptAsset, nullptr, &fn);
    napi_set_named_property(env, exports, "decryptAsset", fn);

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
