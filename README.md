# Chronos-Builder-Template V2.2

云端编译模板 — Fork 到私有仓库，一键生成专属 `.node` 加密文件。

> 📌 **本仓库为 Chronos Seal 的云端编译模板仓库，仅用于 Fork 后运行 GitHub Actions。**
>
> 如需提交 Issue、查看完整文档或了解项目详情，请移步主仓库：
> [https://github.com/CLARE-XHL/Chronos-Seal](https://github.com/CLARE-XHL/Chronos-Seal)

> ⚠️ **本模板仅用于 RPG Maker MZ。** RPG Maker MV 采用纯 JS 轻量防护，无需云端编译，请前往主仓库获取 MV 版本。


## 使用方法

**1. Fork 本仓库（必须设为私有）**

**2. 触发 Actions**
Actions → Build Chronos Seal → Run workflow → 填写参数（游戏名称、版本号）

> V2.2 已移除"截止日期"参数——过期检查机制已废弃。作者只需填写游戏名称与版本号。

**3. 下载产物**
编译完成后下载 artifact `chronos-seal-output-MZ`，解压得到：

- `decryptor.node` —— 放入游戏发行包根目录
- `encrypt_config.json` —— 本地加密阶段使用，**首次构建后必须长期保存**
- `author_secret.txt` —— 离线保存，绝对不要放进游戏包

**4. 保存凭证后删除 Fork 仓库**
下载后立即删除 Fork，确保日志和密钥不泄露。

> 🔑 **重要**：`encrypt_config.json` 与 `author_secret.txt` 包含主种子，是后续所有增量补丁的基础。**丢失后无法再更新已发布的游戏**，请务必离线备份（私有仓库 / 云盘 / 离线介质）。


## 编译流程说明

本模板的 GitHub Actions 工作流执行以下步骤：

1. 校验输入（游戏名称 1-64 字符，版本号仅字母数字与 `. _ -`）
2. 计算构建日期
3. 安装 Node.js 18.x / Python 3.10 / node-gyp 9.4.0
4. **生成分片种子**（4 段随机种子 + 盐）
5. **生成字符串密文表**（`cs_str_table.h`，用于替换二进制中的明文 tag）
6. **生成 `build_config.h`**（将种子、版本号、日期写入 C++ 编译期常量）
7. 编译 `decryptor.node`（VS2022 x64）
8. 生成 `encrypt_config.json` 与 `author_secret.txt`
9. **三重产物校验**：
   - 产物存在性
   - 二进制中无明文 tag
   - 种子已正确编入二进制
10. 上传 artifact

任一校验步骤失败 → Actions 直接红，防止"静默降级到源码默认值"。


## 与主仓库的关系

- [Chronos-Seal](https://github.com/CLARE-XHL/Chronos-Seal)：主仓库，含源码与完整文档
- [Chronos-Builder-Template](https://github.com/CLARE-XHL/Chronos-Builder-Template)：本仓库，云端编译模板


## 版本兼容

- 本模板对应 **Chronos Seal V2.2**。
- V2.2 与 V2.1 的加密格式**不兼容**。如果你是从 V2.1 升级，需要重新加密所有素材。
- 老版本游戏不受影响，可继续正常运行。


## 完整文档

详细使用说明请查看：[Chronos Seal 文档站](https://docs.crclare.top)


## 许可证

本项目采用 MIT 许可证开源，详见 [LICENSE](LICENSE) 文件。

使用本软件时，请遵守以下约定：

- ✅ 允许：将 Chronos Seal 集成到你的商业或免费游戏中，闭源售卖你的游戏
- ✅ 允许：修改源码用于你自己的项目
- ✅ 允许：在遵守 MIT 协议的前提下进行分发
- ❌ 严禁：将 Chronos Seal 的源码或编译产物（`.node` 文件）作为独立商品直接售卖
- ❌ 严禁：删除或隐藏版权声明后销售 Chronos Seal 本体

**简单来说：你可以卖用了 Chronos Seal 的游戏，但不能直接卖 Chronos Seal 本身。**

---

*本声明是对 MIT 许可证的补充说明，不改变 MIT 许可证的授权条款。*


**⭐ 如果这个项目对你有帮助，请给主仓库一个 Star！**
