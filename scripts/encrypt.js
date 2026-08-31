/**
 * Chronos Seal V2.0 - 加密脚本
 * 用于 GitHub Actions 云端编译
 * 读取 system.json，用动态生成的密钥加密，输出 system.json.enc
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 从命令行参数获取 IV（由 GitHub Actions 生成）
const ivHex = process.argv[2];
if (!ivHex || ivHex.length !== 32) {
    console.error('❌ 错误: 需要 32 字符的 IV 参数 (16 字节十六进制)');
    console.error('用法: node encrypt.js <iv_hex>');
    process.exit(1);
}

const iv = Buffer.from(ivHex, 'hex');
if (iv.length !== 16) {
    console.error('❌ 错误: IV 必须是 16 字节');
    process.exit(1);
}

// ============================================================
// 从 src/config.h 读取派生密钥
// ============================================================
function deriveKeyFromConfig() {
    const configPath = path.join(__dirname, '..', 'src', 'config.h');
    if (!fs.existsSync(configPath)) {
        console.error('❌ 错误: src/config.h 不存在，请先运行 build.yml');
        process.exit(1);
    }

    const content = fs.readFileSync(configPath, 'utf8');

    // 提取 GAME_VERSION
    const versionMatch = content.match(/GAME_VERSION\s*=\s*"([^"]+)"/);
    if (!versionMatch) {
        console.error('❌ 错误: 无法从 config.h 提取 GAME_VERSION');
        process.exit(1);
    }
    const gameVersion = versionMatch[1];

    // 提取 RELEASE_DATE
    const dateMatch = content.match(/RELEASE_DATE\s*=\s*"([^"]+)"/);
    if (!dateMatch) {
        console.error('❌ 错误: 无法从 config.h 提取 RELEASE_DATE');
        process.exit(1);
    }
    const releaseDate = dateMatch[1];

    // 提取 DERIVATION_SEED
    const seedMatch = content.match(/DERIVATION_SEED\s*=\s*"([^"]+)"/);
    if (!seedMatch) {
        console.error('❌ 错误: 无法从 config.h 提取 DERIVATION_SEED');
        process.exit(1);
    }
    const derivationSeed = seedMatch[1];

    // 派生密钥: HMAC-SHA256(种子, 版本号 + 日期)
    const data = gameVersion + releaseDate;
    const key = crypto.createHmac('sha256', derivationSeed)
        .update(data)
        .digest();

    console.log(`📌 版本号: ${gameVersion}`);
    console.log(`📌 发行日期: ${releaseDate}`);
    console.log(`📌 密钥派生: HMAC-SHA256(种子, "${gameVersion}${releaseDate}")`);

    return key;
}

// ============================================================
// 读取并加密 system.json
// ============================================================
function encryptSystemJson() {
    const inputPath = path.join(__dirname, '..', 'system.json');
    const outputPath = path.join(__dirname, '..', 'system.json.enc');

    if (!fs.existsSync(inputPath)) {
        console.error('❌ 错误: system.json 不存在，请将其放在仓库根目录');
        process.exit(1);
    }

    console.log('📦 读取 system.json...');
    const plaintext = fs.readFileSync(inputPath);

    console.log('🔑 派生发行密钥...');
    const key = deriveKeyFromConfig();

    console.log('🎲 使用 IV:', ivHex);

    // AES-256-CBC 加密
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    // 写入文件（格式：IV + 密文）
    const output = Buffer.concat([iv, encrypted]);
    fs.writeFileSync(outputPath, output);

    console.log('✅ 加密完成: system.json.enc');
    console.log(`📊 原始大小: ${plaintext.length} bytes`);
    console.log(`📊 加密大小: ${encrypted.length} bytes`);

    // 输出校验
    if (!fs.existsSync(outputPath)) {
        console.error('❌ 错误: system.json.enc 未能成功写入');
        process.exit(1);
    }

    console.log('✅ 校验通过: system.json.enc 已生成');
}

// ============================================================
// 执行
// ============================================================
try {
    encryptSystemJson();
} catch (err) {
    console.error('❌ 加密过程发生异常:', err.message);
    process.exit(1);
}
