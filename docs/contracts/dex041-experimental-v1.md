# 显式 DEX 041 容器实验入口

041 的 `file_size` 是逻辑头到下一头/容器末尾的距离；所有偏移基于物理文件，允许引用后续共享数据，header 为 120 字节，`container_size/header_offset` 交叉描述边界，旧 data_size/data_off 不再定义连续数据段。依据 [AOSP DEX 格式](https://source.android.com/docs/core/runtime/dex-format) 和固定修订 [ART header](https://android.googlesource.com/platform/art/+/ef21fb5f2520c604a6d5659452488a93433ee85a/libdexfile/dex/dex_file.h)、[ART verifier](https://android.googlesource.com/platform/art/+/ef21fb5f2520c604a6d5659452488a93433ee85a/libdexfile/dex/dex_file_verifier.cc) 核实；不将该实验格式宣称为稳定生产能力。

默认 `read_metadata`、旧 C open API 和普通 CLI 继续拒绝 041。新增内部 `dex041::enumerate`、`read_metadata_041` 和公共 `dmg_snapshot_open_dex041_copy_v1`，后者要求 `experimental_041=1`、明确源范围与最大逻辑数。旧公开 struct 不改，新增有 size 检查的 `dmg_dex041_*_v1`；独立 `dmg_dex041_capability_v1()` 公布实验能力，不加入默认稳定 profile 字符串。

物理 bytes 只复制一次，由所有逻辑 Source 共享持有；每个 Source 各有自己的 Facts、header_offset 和逻辑文件大小。Content/ContainerId 使用完整物理容器长度及 SHA-256，LogicalDexId 加入逻辑头偏移，occurrence 绑定 namespace/slot/role/logical identity，重复 ordinal 不跨头合并。Result/Batch 持有的 Dataset 继续持有物理存储。专用 source-info getter 返回 container/header/逻辑 extent；普通 Source 的 byte span/摘要仍覆盖完整容器，Dataset dex_bytes 按逻辑 extent 合计，避免按头数重复计物理字节。

Reader 的 header 字段与 data 偏移分开寻址；数据读取禁止早于选中头或覆盖其他逻辑头。map/header/table、container_size/header_offset、逻辑 extent 和 item 范围共同检查。041 章节间可以存在其他逻辑 DEX 的内容，不套用标准格式连续零 padding 假设；选定字符串 ID 从实际共享 string_data 项起点索引读取，允许共享池包含其他逻辑头使用的条目。其他既有元数据项仍经过原有有界解析，不伪造或修改输入头来借用 035 解析。

Facts 新增 header_offset/logical_file_size/container_size（标准格式 header_offset=0）。实体表 record offset 使用对应逻辑头的表地址。Decoder 新增默认 false 的 experimental_041；只有显式041 Facts 的普通 method collector 接通该选项。标准 query/source 身份域不变，041 Source/Snapshot 身份另行隔离。

`reference::execute` 集中检查041来源：本批开放基础 metadata/集合/关系/普通use/展开及 v21/v22 类型使用所需能力；高级继承、反射、数值、streaming 等未经核对的高位组合明确 Unsupported，覆盖 sync/Job/multi 和内部入口。CFG/dataflow/debug 关联等其他直接 decoder 入口尚未传041选项，不能据本批声称其支持。现有持久缓存的键不含 header_offset，本批配合正式 provider 的版本准入对041绕过持久片和解析memo，不以相同物理摘要+ordinal跨头复用；未来要缓存041需独立逻辑键/格式版本。

可选桌面工具 `DMG_BUILD_DEX041_TOOL=ON` 生成 `dexmeguviz_041 inspect CONTAINER` 与 `dexmeguviz_041 query CONTAINER QUERY.json`。工具查询输出当前支持 direct v1/v2 的实体/方法摘要；更广泛但已准入的查询可用 C API。没有新增 APK 中041的自动展开、borrowed/fd041 API、Android Java入口或新 AAR。

SQLite 适配器尚有直接读取物理字节的旧 header-zero 路径，不经过 `reference::execute`；因此 `SqlSession::open_impl` 对含任一041来源的 Snapshot 统一返回 `SQLITE_MISMATCH`（本适配器的 unsupported 映射），在创建连接/注册表前拒绝，out 保持不变。这覆盖普通、scoped 和 planned 会话入口。仅修准入，不把单个 raw_mutf8 偏移修正宣称为完整 SQL041 支持；标准035–040行为不变。

本轮 Release core/CLI 编译和少量自建连通通过：两个真正041头在0/120，同用后续字符串池；方法字符串查询命中两个不同owner；method_refs记录地址分别304/312；默认CLI明确拒绝。生成器按固定 [ART checksum 实现](https://android.googlesource.com/platform/art/+/ef21fb5f2520c604a6d5659452488a93433ee85a/libdexfile/dex/dex_file.cc) 填入逻辑 extent 的校验字段，但新入口和原metadata默认行为一样，不宣称已执行DEX Adler/SHA1验真；强摘要覆盖整个container。

未执行完整041合法/非法语料矩阵、所有共享段组合、来源生命周期/取消/故障/并发专项、Android双ABI或ART。未知map类型与未实现路径明确拒绝，部分旧元数据约束可能仍拒绝官方格式的其他合法共享布局，不能称完整041 verifier。首次工具max_jobs漏设和method_refs使用旧method-only info getter均已修复；provider重基时保留文件mtime使构建漏编依赖而链接失败，触发相关源重编后通过，原记录保留。P4-07保持进行中。

041是raw物理容器，Source的ZIP CRC及local/central头一致性证据保持false；结构检查由Input.container_metadata_checked及专用041 source-info表达，不能复用归档检查位。

现有 snapshot/result 的 `dmg_*_check_dex_checksums_v1` 只实现标准单头extent；对041来源直接返回 `DMG_UNSUPPORTED` 且不写out，避免在第二逻辑Source上错误检查第一头和整容器尾部。041的Adler/SHA1显式验真尚未实现，强摘要身份仍覆盖完整容器。
