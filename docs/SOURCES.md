# DexMeguviz 工程资料索引

本索引以 2026-10-26 审阅的固定源码和官方文档为依据。实际实现先核实当前checkout差异；固定commit用于复查，不是“最新版本”承诺。研究报告中的性能区间是待验证目标。公开资料未包含DexSQL核心源码，不能据接口类型名猜测其内部实现。

| ID | 资料 | 用途与边界 |
| --- | --- | --- |
| B1 | [BIL 查询接口与枚举](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/adapter/dex/DexAssistEngine.kt) | 33规则、输出形态与session；执行前复核当前commit |
| B2 | [BIL DexKit 实现](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/adapter/dex/DexKitAssistEngine.kt) | 旧DSL、批次、关系与结果转换 |
| B3 | [BIL VersionAdapter](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/VersionAdapter.kt) | 业务计划、缓存、重试与绑定 |
| B4 | [BIL 尝试保护](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/adapter/dex/DexAssistAttemptGuard.kt) | admission与恢复入口，迁移仍需完整状态测试 |
| B5 | [BIL Gradle 构建](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/build.gradle.kts) | 工具链pin、ABI、c++_static、测试入口 |
| B6 | [BIL 原生构建](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/cpp/CMakeLists.txt) | 当前C++17与既有依赖 |
| B7 | [BIL Semantics 验真](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/hostui/chrome/HostComposeSemanticsAccess.kt) | canonical key与已有静态读取/展示调用 |
| B8 | [BIL Speed 验真](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/main/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/adapter/PlayerSpeedLocator.kt) | 构造样本和字段验证 |
| B9 | [BIL 历史宿主矩阵](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/docs/host-9.16.0-adaptation.md) | 历史记录不是本轮真实APK测量 |
| B10 | [BIL 宿主设备 runner](https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/984b96dff1c09f355449d973a10be46b68fa27a2/Bilibili_Innocent_Lab/app/src/androidTest/java/com/Bilibili_Innocent_Lab/xposedmodule/hook/HostApkCompatibilityInstrumentedTest.kt) | 参数/skip/运行范围，需扩展A/B/C与split |
| D1 | [DexKit MethodMatcher](https://github.com/LuckyPray/DexKit/blob/c9cd12a14b75409bebd2f73e4dfc5ff575df3eb8/dexkit/src/main/java/org/luckypray/dexkit/query/matchers/MethodMatcher.kt) | modifiers默认Contains，反射flags与accessFlags域 |
| D2 | [DexKit native matcher](https://github.com/LuckyPray/DexKit/blob/c9cd12a14b75409bebd2f73e4dfc5ff575df3eb8/Core/dexkit/dex_item_matcher.cpp) | 多个matcher的覆盖与匹配语义 |
| D3 | [DexKit 能力需求分析](https://github.com/LuckyPray/DexKit/blob/c9cd12a14b75409bebd2f73e4dfc5ff575df3eb8/Core/dexkit/analyze.cpp) | 正反向关系需求；不可假定每条query重建 |
| A1 | [AOSP DexFileLoader](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file_loader.cc) | mmap/extract、verify gate、标准输入与容器 |
| A2 | [AOSP ZipEntry](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libartbase/base/zip_archive.cc) | 映射/提取路径与对齐 |
| A3 | [AOSP libziparchive](https://android.googlesource.com/platform/system/libziparchive/+/3861cb86976b51f61193255f61b7bcf99c5f2918/zip_archive.cc) | 元数据、解压、CRC策略；不同stream需另核对 |
| A4 | [AOSP DexFileVerifier](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file_verifier.cc) | 结构验证、checksum和code item检查边界 |
| A5 | [AOSP DexInstruction](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_instruction.cc) | payload长度与先验验证 |
| A6 | [AOSP DexFile](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_file.cc) | 有序ID表查找与checksum范围 |
| A7 | [AOSP ClassAccessor](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/class_accessor-inl.h) | class_data的delta与访问前提 |
| A8 | [AOSP DEX格式](https://source.android.com/docs/core/runtime/dex-format) | 稳定版本、MUTF-8与041容器规范 |
| A9 | [AOSP opcode表](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/dex_instruction_list.h) | 生成版本化解码元数据时的固定依据 |
| A10 | [AOSP LEB128](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libartbase/base/leb128.h) | 边界安全与兼容输入策略区分 |
| A11 | [AOSP 紧凑索引](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/type_lookup_table.cc) | 两阶段建表与部分hash后精确核对 |
| A12 | [AOSP CompactOffsetTable](https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/libdexfile/dex/compact_offset_table.cc) | 稀疏偏移压缩的备选算法 |
| S1 | [SQLite virtual tables](https://sqlite.org/vtab.html) | 规划/过滤/残余与排序承诺 |
| S2 | [SQLite index_info](https://sqlite.org/c3ref/index_info.html) | usable、colUsed与估计信息 |
| S3 | [SQLite all-at-once IN](https://sqlite.org/c3ref/vtab_in.html) | 批量IN接口 |
| X1 | [DexSQL 数据模型](https://dexsql.lsposed.org/docs/sql/data-model) | 公开引用/定义/作用域语义 |
| X2 | [DexSQL SQL语义](https://dexsql.lsposed.org/docs/sql/) | LIKE/ESCAPE、文本与会话定义；读取日期2026-10-26 |
| X3 | [DexSQL MCP生命周期](https://dexsql.lsposed.org/docs/mcp/lifecycle) | 队列/取消与dataset生命周期 |
| X4 | [DexSQL MCP查询](https://dexsql.lsposed.org/docs/mcp/query) | 输出与分页边界 |
| X5 | [DexSQL benchmark条件](https://github.com/LSPosed/dexsql-release/blob/b867cfeb33da3d3dc32c74d6f05c741eb60586b2/benchmarks/agent-audit/README.md) | 桌面会话口径不能映射手机 |
| X6 | [DexSQL发布工作流](https://github.com/LSPosed/dexsql-release/blob/b867cfeb33da3d3dc32c74d6f05c741eb60586b2/.github/workflows/release.yml) | 私有核心构建与公开平台构件边界 |
| N1 | [Android JNI](https://developer.android.com/ndk/guides/jni-tips) | JNI线程/引用/批量与快速native约束 |
| N2 | [Android页大小](https://developer.android.com/guide/practices/page-sizes) | 4KB/16KB包装与运行检查 |
| N3 | [Android PGO](https://developer.android.com/ndk/guides/pgo) | 代表性profile与显式采集 |
| P1 | [第一轮研究报告](https://chatgpt.com/space/page_2cec8d63ec24819197dd57f6ddb916df) | BIL耦合审计；私人页面可读性不作为实现前置 |
| P2 | [第二轮研究报告](https://chatgpt.com/space/page_ef6385219ca0819190c4d429133b5ef8) | 可复用架构、DexSQL和AOSP深化；早期暂名已统一为DexMeguviz |

若引用源码片段，保留对应许可证、版权与修改说明。文件格式规范、受控验证器和微基准不能自动证明所有Android设备或宿主版本均兼容。BIL运行时verifier清单和具体规则来源另见工程计划附录A。

