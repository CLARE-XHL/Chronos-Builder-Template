/**
 * ============================================================
 * Chronos Seal — Time as the seal, action as the key,
 * time itself guards originality.
 * This freedom is dedicated to every independent creator,
 * and to that visitor, Liberty, who has not set foot on the island
 * in a long time.
 * ============================================================
 *
 * Chronos Seal 2.0 - decryptor.cc
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
 * 版本: 2.0
 * 日期: 2026-08-31
 *
 * 核心改进 (V2.0 极简主义):
 *   - 完全移除 Steam SDK 依赖
 *   - 完全移除硬件指纹 / 机器绑定
 *   - 完全移除注册表 / ADS 双存储
 *   - 完全移除 config.bin 外部配置
 *   - 所有密钥 (盐值、IV、检查点白名单) 在云端编译时硬编码进二进制
 *   - 用户只需下载专属 .node 文件，无需任何额外配置
 *
 * 设计哲学:
 *   - 经济学博弈: 让破解成本 > 游戏售价
 *   - 版本更新差: 旧版本自动失效，不靠硬编码时间炸弹
 *   - 零信任: 密钥只在用户自己的 GitHub Actions 中生成，作者不接触
 *   - 完全可逆: 加密只针对发行包，工程文件零修改
 */

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

#include "config.h"  // V2.0：由 GitHub Actions 云端动态生成


// ============================================================
// 编译开关
// ============================================================

// #define WATCHDOG_LOGGING  // Release 版请注释掉


// ============================================================
// 错误码定义（二进制仅返回数字）
// ============================================================

enum ErrorCode {
    SUCCESS = 0,
    ERR_EXPIRED = 10,
    ERR_SIGNATURE = 30,
    ERR_NO_RES = 40,
    ERR_UNKNOWN = -1
};


// ============================================================
// 全局状态
// ============================================================

// 看门狗
std::atomic<bool> g_heartbeat_received(false);
std::atomic<int> g_missed_heartbeats(0);
std::atomic<bool> g_watchdog_exit(false);
std::thread g_watchdog_thread;
std::mutex g_watchdog_mutex;
bool g_watchdog_started = false;

// 检查点哈希链（单向 HMAC 迭代）
std::atomic<uint64_t> g_checkpoint_chain_hash(0);
std::mutex g_checkpoint_mutex;

// 上次盐值（全局原子，防内存 Patch）
std::atomic<double> g_last_salt(0.0);


// ============================================================
// 日志辅助（编译开关控制）
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
// Base64 编解码
// ============================================================

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

/**
 * Base64 解码 - 严格模式
 * 遇到非法字符直接返回空串
 */
std::string base64_decode(const std::string& encoded) {
    static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (char c : encoded) {
        if (c == '=') break;
        size_t pos = b64.find(c);
        if (pos == std::string::npos) {
            return "";  // 非法字符 → 拒绝
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


// ============================================================
// HMAC-SHA256
// ============================================================

std::string hmac_sha256(const std::string& data, const std::string& salt) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(),
         salt.c_str(), static_cast<int>(salt.size()),
         reinterpret_cast<const unsigned char*>(data.c_str()),
         data.size(),
         result, &len);
    return std::string(reinterpret_cast<char*>(result), len);
}

/**
 * 将 HMAC 结果前 8 字节转为 uint64_t
 */
uint64_t hmac_to_uint64(const std::string& hmac_result) {
    uint64_t value = 0;
    for (size_t i = 0; i < std::min(hmac_result.size(), sizeof(uint64_t)); ++i) {
        value = (value << 8) | static_cast<unsigned char>(hmac_result[i]);
    }
    return value;
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

bool delete_file(const std::string& path) {
    return std::remove(path.c_str()) == 0;
}


// ============================================================
// V2.0：密钥派生函数（从 config.h 读取硬编码配置）
// ============================================================

/**
 * 派生发行密钥
 * 公式： HMAC-SHA256(派生种子, 游戏版本号 + 发行日期)
 * 开发者打包时和用户首次启动时使用相同参数，派生结果一致
 */
std::string derive_release_key() {
    std::string data = Config::GAME_VERSION + Config::RELEASE_DATE;
    return hmac_sha256(data, Config::DERIVATION_SEED);
}

/**
 * V2.0：解密 system.json.enc（使用发行密钥）
 * 注意：V2.0 不再需要用户密钥，因为不绑定机器
 */
std::string decrypt_system_json(const std::string& ciphertext, const std::string& iv) {
    return aes_decrypt(ciphertext,
        reinterpret_cast<const unsigned char*>(derive_release_key().c_str()), iv);
}


// ============================================================
// 时间哈希与校验
// ============================================================

std::string hex_encode(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

/**
 * 校验硬截止时间（从 config.h 读取）
 */
bool is_expired() {
    time_t now = time(nullptr);
    return now > Config::HARD_EXPIRE;
}


// ============================================================
// AES-256-CBC 加解密（随机 IV）
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

std::string aes_decrypt(const std::string& ciphertext, const unsigned char* key,
                        const std::string& iv) {
    if (iv.size() != 16) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key,
                       reinterpret_cast<const unsigned char*>(iv.c_str()));

    int len = 0, total = 0;
    std::string plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), '\0');

    if (!EVP_DecryptUpdate(ctx,
                           reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                           reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                           static_cast<int>(ciphertext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    total = len;

    if (!EVP_DecryptFinal_ex(ctx,
                             reinterpret_cast<unsigned char*>(&plaintext[total]), &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    total += len;
    plaintext.resize(total);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}


// ============================================================
// V2.0：核心验证函数（极简版）
// ============================================================

Napi::Object VerifyAndDecrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);

    // ---- 1. 检查时间炸弹 ----
    if (is_expired()) {
        result.Set("success", Napi::Boolean::New(env, false));
        result.Set("errorCode", Napi::Number::New(env, ERR_EXPIRED));
        return result;
    }

    // ---- 2. 检查 system.json.enc 是否存在 ----
    std::string enc_path = Config::SYSTEM_JSON_ENC_PATH;
    if (!file_exists(enc_path)) {
        result.Set("success", false);
        result.Set("errorCode", Napi::Number::New(env, ERR_NO_RES));
        return result;
    }

    // ---- 3. 读取 system.json.enc（格式：IV + 密文） ----
    std::string enc_data = read_file(enc_path);
    if (enc_data.empty() || enc_data.size() < 16) {
        result.Set("success", false);
        result.Set("errorCode", Napi::Number::New(env, ERR_UNKNOWN));
        return result;
    }

    std::string iv = enc_data.substr(0, 16);
    std::string ciphertext = enc_data.substr(16);

    // ---- 4. 解密 ----
    std::string system_json = decrypt_system_json(ciphertext, iv);
    if (system_json.empty()) {
        result.Set("success", false);
        result.Set("errorCode", Napi::Number::New(env, ERR_UNKNOWN));
        return result;
    }

    // ---- 5. 返回成功 ----
    result.Set("success", Napi::Boolean::New(env, true));
    result.Set("errorCode", Napi::Number::New(env, SUCCESS));
    result.Set("systemJson", Napi::String::New(env, system_json));
    return result;
}


// ============================================================
// 检查点验证（单向 HMAC 哈希链 + 强制副作用）
// ============================================================

/**
 * 检查点失败时注入强制副作用
 * 修改 JS 层游戏变量，即使破解者忽略返回值，游戏逻辑也被破坏
 */
void apply_checkpoint_penalty(Napi::Env env) {
    Napi::Object global = env.Global();

    // ---- 1. 清空金钱 ----
    Napi::Value gamePartyVal = global.Get("$gameParty");
    if (gamePartyVal.IsObject()) {
        Napi::Object gameParty = gamePartyVal.As<Napi::Object>();
        gameParty.Set("_gold", Napi::Number::New(env, 0));
    }

    // ---- 2. 传送回原点 ----
    Napi::Value gamePlayerVal = global.Get("$gamePlayer");
    if (gamePlayerVal.IsObject()) {
        Napi::Object gamePlayer = gamePlayerVal.As<Napi::Object>();
        gamePlayer.Set("_x", Napi::Number::New(env, 0));
        gamePlayer.Set("_y", Napi::Number::New(env, 0));
        gamePlayer.Set("_direction", Napi::Number::New(env, 2));
    }

    // ---- 3. 破坏关键开关 ----
    Napi::Value gameSwitchesVal = global.Get("$gameSwitches");
    if (gameSwitchesVal.IsObject()) {
        Napi::Object gameSwitches = gameSwitchesVal.As<Napi::Object>();
        Napi::Function setSwitch = gameSwitches.Get("setValue").As<Napi::Function>();
        if (setSwitch.IsFunction()) {
            setSwitch.Call(gameSwitches, {
                Napi::Number::New(env, 1),
                Napi::Boolean::New(env, false)
            });
        }
    }
}

Napi::Boolean CheckpointVerify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // ---- 1. 参数校验 ----
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Need salt and context").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    double salt_double = info[0].As<Napi::Number>().DoubleValue();
    std::string context = info[1].As<Napi::String>().Utf8Value();

    // ---- 2. 检查是否在白名单中（从 config.h 读取） ----
    auto it = std::find(Config::CHECKPOINT_WHITELIST.begin(),
                        Config::CHECKPOINT_WHITELIST.end(),
                        context);
    if (it == Config::CHECKPOINT_WHITELIST.end()) {
        apply_checkpoint_penalty(env);
        return Napi::Boolean::New(env, false);
    }

    // ---- 3. 单向 HMAC 哈希链校验 ----
    uint64_t current_hash = g_checkpoint_chain_hash.load();
    size_t expected_index = current_hash % Config::CHECKPOINT_WHITELIST.size();
    const std::string& expected_context = Config::CHECKPOINT_WHITELIST[expected_index];

    if (context != expected_context) {
        apply_checkpoint_penalty(env);
        return Napi::Boolean::New(env, false);
    }

    // ---- 4. 盐值防冻结检查 ----
    double last_salt = g_last_salt.load();
    if (salt_double == last_salt) {
        apply_checkpoint_penalty(env);
        return Napi::Boolean::New(env, false);
    }
    g_last_salt.store(salt_double);

    // ---- 5. 单向 HMAC 迭代更新哈希链 ----
    std::string mix_data = context + std::to_string(salt_double);
    std::string mix_hash = hmac_sha256(mix_data, Config::HMAC_SALT);
    uint64_t mix_value = hmac_to_uint64(mix_hash);

    std::string chain_data = std::to_string(current_hash) + std::to_string(mix_value);
    std::string chain_hash = hmac_sha256(chain_data, Config::HMAC_SALT);
    uint64_t new_hash = hmac_to_uint64(chain_hash);

    // CAS 自旋更新
    uint64_t old_hash = current_hash;
    while (!g_checkpoint_chain_hash.compare_exchange_weak(old_hash, new_hash)) {
        std::string new_chain_data = std::to_string(old_hash) + std::to_string(mix_value);
        std::string new_chain_hash = hmac_sha256(new_chain_data, Config::HMAC_SALT);
        new_hash = hmac_to_uint64(new_chain_hash);
    }

    return Napi::Boolean::New(env, true);
}


// ============================================================
// 看门狗守护线程
// ============================================================

void watchdog_thread_func() {
    while (!g_watchdog_exit.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(Config::WATCHDOG_TIMEOUT_SEC));

        if (g_watchdog_exit.load()) break;

        if (!g_heartbeat_received) {
            g_missed_heartbeats++;
            write_watchdog_log("Missed heartbeat #" + std::to_string(g_missed_heartbeats.load()));
            if (g_missed_heartbeats >= Config::WATCHDOG_MAX_MISS) {
                write_watchdog_log("Watchdog triggered! Exiting process.");
                std::exit(0);
            }
        } else {
            g_missed_heartbeats = 0;
            g_heartbeat_received = false;
            write_watchdog_log("Heartbeat received, resetting counter.");
        }
    }
    write_watchdog_log("Watchdog thread exiting normally.");
}

void StartWatchdog(const Napi::CallbackInfo& info) {
    std::lock_guard<std::mutex> lock(g_watchdog_mutex);
    if (!g_watchdog_started) {
        g_watchdog_exit = false;
        g_heartbeat_received = true;
        g_missed_heartbeats = 0;
        g_watchdog_thread = std::thread(watchdog_thread_func);
        g_watchdog_thread.detach();
        g_watchdog_started = true;
        write_watchdog_log("Watchdog started.");
    }
}

void StopWatchdog(const Napi::CallbackInfo& info) {
    g_watchdog_exit = true;
    g_watchdog_started = false;
    write_watchdog_log("Watchdog stop signal sent.");
}

void HeartbeatReply(const Napi::CallbackInfo& info) {
    g_heartbeat_received = true;
    g_missed_heartbeats = 0;
}


// ============================================================
// Node-API 模块注册
// ============================================================

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("verifyAndDecrypt", Napi::Function::New(env, VerifyAndDecrypt));
    exports.Set("checkpointVerify", Napi::Function::New(env, CheckpointVerify));
    exports.Set("startWatchdog", Napi::Function::New(env, StartWatchdog));
    exports.Set("stopWatchdog", Napi::Function::New(env, StopWatchdog));
    exports.Set("heartbeatReply", Napi::Function::New(env, HeartbeatReply));
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
