# Chronos-Builder-Template V2.1

云端编译模板 — Fork 到私有仓库，一键生成专属 .node 加密文件。


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

MIT

**⭐ 如果这个项目对你有帮助，请给主仓库一个 Star！**
