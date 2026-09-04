# Chronos-Builder-Template V2.1

云端编译模板 — Fork 到私有仓库，一键生成专属 .node 加密文件。

> 📌 **本仓库为 Chronos Seal 的云端编译模板仓库，仅用于 Fork 后运行 GitHub Actions。**
> 
> 如需提交 Issue、查看完整文档或了解项目详情，请移步主仓库：
> [https://github.com/CLARE-XHL/Chronos-Seal](https://github.com/CLARE-XHL/Chronos-Seal)


## 使用方法

**1. Fork 本仓库（必须设为私有）**

**2. 上传 `system.json`**
将游戏工程中的 `data/system.json`（明文）上传到仓库根目录。

**3. 触发 Actions**
Actions → Build Chronos Seal → Run workflow → 填写参数（游戏名称、版本号、截止日期）

**4. 下载产物**
编译完成后下载 `chronos-seal-output.zip`，解压得到：
- `decryptor.node` —— 放入游戏发行包根目录
- `encrypt_config.json` —— 本地加密阶段使用
- `author_secret.txt` —— 离线保存，绝对不要放进游戏包！

**5. 删除 Fork 仓库**
下载后立即删除，确保日志和密钥不泄露。


## 完整文档

详细使用说明请查看：[Chronos Seal 文档站](https://docs.crclare.top)


## 与主仓库的关系

- [Chronos-Seal](https://github.com/CLARE-XHL/Chronos-Seal)：主仓库
- [Chronos-Builder-Template](https://github.com/CLARE-XHL/Chronos-Builder-Template)：本仓库


## 许可证

本项目采用 MIT 许可证开源，详见 [LICENSE](LICENSE) 文件。

使用本软件时，请遵守以下约定：

- ✅ 允许：将 Chronos Seal 集成到你的商业或免费游戏中，闭源售卖你的游戏
- ✅ 允许：修改源码用于你自己的项目
- ✅ 允许：在遵守 MIT 协议的前提下进行分发
- ❌ 严禁：将 Chronos Seal 的源码或编译产物（.node 文件）作为独立商品直接售卖
- ❌ 严禁：删除或隐藏版权声明后销售 Chronos Seal 本体

**简单来说：你可以卖用了 Chronos Seal 的游戏，但不能直接卖 Chronos Seal 本身。**

---

*本声明是对 MIT 许可证的补充说明，不改变 MIT 许可证的授权条款。*


**⭐ 如果这个项目对你有帮助，请给主仓库一个 Star！**
