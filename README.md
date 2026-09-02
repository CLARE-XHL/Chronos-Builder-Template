# Chronos Seal V2.1 — 云端编译模板

> **此仓库是模板仓库，不要直接使用。请 Fork 到自己的 GitHub 账户，并设为私有仓库。**

---

## 这是什么？

这是 Chronos Seal V2.1 的云端编译模板。你不需要在本地安装任何编译工具（不需要 Node.js、Python、MSVC、OpenSSL），只需要：

1. Fork 本仓库（设为私有）
2. 放入你的 `system.json`
3. 在 GitHub Actions 中填写游戏名称和版本号
4. 等待 2-3 分钟，下载专属的 `.node` 和配置文件
5. 删除 Fork 仓库（日志销毁，密钥不泄露）

---

## 前置条件

在开始之前，你需要准备好以下内容：

1. 下载 Chronos Seal V2.1 发行包
2. 将 `auth_manager.js` 放入 `js/plugins/` 目录
3. 在 RPG Maker 插件管理器中启用 `auth_manager.js`
4. 在公共事件中配置 `AuthManager.initialize()` 和心跳
5. 准备好你的 `system.json`（游戏工程中的 `data/system.json`，明文）

> ⚠️ V2.1 不再需要 `config.h`，也不需要运行 `ChronosScan.bat`。

---

## 使用步骤

### 第一步：Fork 本仓库

1. 点击右上角的 **Fork** 按钮
2. **重要：** 在 Fork 选项中，**必须将仓库设置为 Private（私有）**
3. 等待 Fork 完成

### 第二步：上传你的文件

将以下文件上传到你的 Fork 仓库根目录：

- `system.json`（你的游戏工程中的 `data/system.json`，明文）

> ⚠️ 不要上传其他文件，不要修改目录结构。

### 第三步：触发 GitHub Actions

1. 在你的 Fork 仓库中，点击上方的 **Actions** 标签
2. 在左侧选择 **Build Chronos Seal**
3. 点击右侧的 **Run workflow** 按钮
4. 填写以下参数：

- 游戏名称：你的游戏名称。示例：MyGame
- 游戏版本号：当前版本号。示例：1.0.0
- 截止日期：时间炸弹截止日期（留空则永不过期）。示例：2027-01-01

5. 点击 **Run workflow**，等待编译完成（约 2-3 分钟）

### 第四步：下载文件

编译完成后，在 Actions 页面底部会生成一个 **Artifacts** 压缩包：

- 文件名：`chronos-seal-output.zip`
- 点击下载

解压后，你会得到三个文件：

- decryptor.node —— C++ 原生插件，放入游戏发行包根目录
- encrypt_config.json —— 素材加密配置，用于本地加密阶段
- author_secret.txt —— 作者专属密钥，离线保存，绝对不要放进游戏包！

### 第五步：部署到游戏

1. 将 `decryptor.node` 放入发行包根目录
2. 将 `encrypt_config.json` 放入发行包根目录（加密阶段使用）
3. 将 `encrypt_assets.bat` 和 `encrypt_assets.js` 放入发行包根目录（从 CS 发行包获取）
4. 双击 `encrypt_assets.bat` 加密所有素材
5. 删除 `encrypt_config.json`、`encrypt_assets.bat`、`encrypt_assets.js`
6. 确保 `index.html` 已替换为 CS 版本
7. 打包发布

### 第六步：删除 Fork 仓库（重要！）

下载文件后，**立即删除你的 Fork 仓库**：

1. 进入你的 Fork 仓库页面
2. 点击 **Settings** → 滚动到底部 → **Delete this repository**
3. 输入仓库名称确认删除

> ⚠️ 删除仓库会同时删除所有 Actions 日志，确保密钥不会泄露。

---

## ⚠️ author_secret.txt 的重要性

`author_secret.txt` 包含：

- 游戏名称和版本号
- 派生种子（Salt）
- 发行日期

**这份文件是游戏加密的唯一凭证。**

- 丢失后无法恢复，加密将永久失效
- 泄露后加密将完全失效
- 建议保存到至少两个不同的物理设备（如本地硬盘 + U盘）
- 绝对禁止随游戏发行包一起发布
- 绝对禁止上传到任何云端存储（除非加密后）

---

## 更新游戏版本

当你要发布游戏更新时：

1. 在 RPG Maker 中修改游戏内容
2. 将新的 `system.json` 上传到你的 Fork 仓库（或重新 Fork）
3. 在 Actions 中输入**新的版本号**
4. 下载新的 `decryptor.node` 和 `encrypt_config.json`
5. 重新运行 `encrypt_assets.bat` 加密素材
6. 替换游戏包中的旧文件，重新发布

旧版本生成的 `.node` 和加密素材会自动失效，因为版本号变了，密钥也随之变化。

---

## 常见问题

Q: 为什么必须设私有仓库？

A: 因为 Actions 日志中会包含密钥信息。私有仓库的日志只有你自己能看，公开仓库的日志全世界都能看。

Q: 我 Fork 了之后，这个模板仓库更新了怎么办？

A: 你的 Fork 是独立的，不会被自动同步。如果需要新功能，可以重新 Fork 最新的模板仓库，或者手动更新你的 Fork。

Q: 编译失败了怎么办？

A: 检查以下几点：
1. `system.json` 是否在仓库根目录（不是子文件夹）
2. 检查 Actions 日志中的错误信息
3. 确认 `system.json` 是合法的 JSON 格式

Q: 我可以多次运行 Actions 吗？

A: 可以。每次运行都会生成新的密钥和 `.node` 文件。旧的 `.node` 文件将无法解密新加密的素材。

Q: V2.1 还需要 `config.h` 吗？

A: 不需要。V2.1 改用 `-D` 宏在编译时传入所有参数，`config.h` 已移除。

Q: V2.1 还需要 `ChronosScan.bat` 吗？

A: 不需要。V2.1 已移除检查点功能，不再需要扫描地图。

---

## 许可证

本模板仓库采用 MIT 许可证。生成的 `.node` 文件版权归游戏作者所有。


**⭐ 如果这个项目对你有帮助，请给主仓库一个 Star！**
