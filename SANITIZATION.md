# 脱敏与公开范围说明

生成日期：2026-11-06。本仓库是 **DexMeguviz 本地工作区的可公开子集**，由只读扫描生成；
原始工作区文件与证据均未被修改，仍保存在本机。

## 导出方式

按目录与扩展名白名单选取源码、契约/状态文档、构建脚本、品牌图标及合规第三方源码，
共 **1116 个文件**；文本按 UTF-8 读取并保留原有换行，二进制（仅品牌 PNG）逐字节复制。
没有沿用本地 `.git` 历史，公开仓库从一次干净的初始提交开始。副本带 `.gitattributes`
（`* -text`）禁用 Git 换行转换，使远端 blob 与 manifest 中记录的公开副本 SHA-256 一致。

## 清洗规则与命中

| 规则 | 命中次数 |
|---|---|
| `readme_note` | 1 |
| `win_abs` | 38 |

本次命中的规则见上表；规则集支持的替换占位符为 `<LOCAL_PATH>`、`<LOCAL_USER>`、
`<DEVICE_SERIAL>`、`<REDACTED_CREDENTIAL>`、`<REDACTED>`、`<EMAIL>`（未命中即未出现于副本）。
这些占位符会让个别文档中的示例命令不再可直接执行，属于刻意脱敏；
实际路径请按本机环境替换。`jichuo1@users.noreply.github.com` 是公开的 Git 提交身份，予以保留。

`SANITIZATION_MANIFEST.json` 记录每个文件的原始 SHA-256、公开副本 SHA-256、是否被清洗及
命中的规则，便于对照原件与副本。

第三方源码（`third_party/miniz`、`third_party/sqlite`）按项目 `THIRD_PARTY_NOTICES` 的约定
**逐字节原样复制、不参与任何清洗**，以保持上游文件哈希；其中的通用示例路径与邮箱
不是本机信息。部分项目文档里的工具链探测路径
（如 `C:\Program Files\...`）同样属于通用环境描述，予以保留。
清洗只针对本地工作区路径、本机身份、设备标识与凭据。

## 未公开内容

- work/（本地运行与采集证据，约 6.7 GB）
- build/（构建产物，约 1.1 GB）
- docs/evidence/（原始证据、日志、DEX/APK 快照，约 2.6 GB）
- integrations/（BIL 第三方客户端适配代码）
- references/engineering-pack/（工程包附件原文与提示词）
- tests 下的 .dex / .apk / .zip 二进制夹具
- tests/fixtures/generated/multisource/ 下 cli-results、query-inputs 生成结果（项目 .gitignore 已忽略）
- hs_err_pid*.log（JVM 崩溃日志）
- __pycache__/、*.pyc、所有构建中间产物
- .git/（本地仓库历史，不沿用）

文档与状态文件中若引用上述路径或"证据""快照""哈希"，仅表示本机可追溯；**公开副本不包含
这些原始证据，不能据此宣称公开可复验或已取得设备、性能与业务资格**。原始日志按项目约定
保留在本机，未做改写，以免破坏已记录的哈希。

## 依赖与许可

`third_party/miniz`（MIT）与 `third_party/sqlite`（public domain）随源码附上，
许可证与固定版本见各自目录及 `THIRD_PARTY_NOTICES`。AOSP 只引用公开的 DEX 格式规范，
未复制其实现源码。项目采用 **Apache License 2.0**（`LICENSE` / `NOTICE`），由所有者于
2026-11-06 决定。未公开的原始二进制夹具与本地证据不在本仓库的分发范围内，其分发条款
仍由所有者决定。`LICENSE`、`NOTICE` 与本节的文字更新是许可证确认后的后续提交，
不属于初始导出快照，因此未列入 `SANITIZATION_MANIFEST.json` 的逐文件哈希清单。

## 已知限制

- 本副本未包含可用于完整复现验证的二进制夹具与设备证据，CI/构建需自行准备依赖与工具链。
- 脱敏基于规则匹配与人工范围核对，不能证明绝对不存在其他敏感内容；如需转为更高可见范围，
  应先对新增内容重新扫描。
