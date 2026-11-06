# JNI v18 使用事实与继承证据（候选）

在同步 `queryUseGraph` 中显式请求 `inherited_fields`、`use_target_symbol`、`inherited_target_symbol` 的 v18 计划，使用新的私有 wire 标识。每条 `DMG_WITNESS_INHERITED` 在既有通用节点、三值和来源实体身份之后，附加 v6 的 item、path、aux、branch 和 detail；`UseGraphResult.Witness.inheritedDetailPresent` 为真时五个只读字段有效，`0xffffffff` 是无索引哨兵。路径及分支索引的解释沿用 [inherited-query-v6.md](inherited-query-v6.md)，按节点和分支分别关联；不把通用 referenceIndex 当作路径。

v18 允许核心支持的显式 scope，`coverage` 和 `profile.scopeComplete` 均按核心返回，不能从未声明的完整来源范围推断运行时全局完整。NativeEngine 的每个来源仍需显式提供，输入快照保持原有不完整声明；显式关闭域是调用方声明的静态查询范围，不证明系统实际没有其他 ClassLoader 来源。v18 的未知、partial 和未解决继承依然保留，不转换成无匹配。

旧 v4/v9/v16 仍使用原始 wire，继续拒绝显式 scope；旧结果中的新字段为无效标记。v18 未新增异步 use-graph Job，其他高级能力、旧 metadata graph 入口仍按原合同拒绝。wire 仅限本进程的新 AAR Java/native 配对，不是持久格式。每个证据和输出总量沿用 100000 items、8 MiB wire、文本/来源等现有 JNI 上限；复制失败不返回半个结果。结果为独立复制，可在关闭快照后读取。

此候选不证明设备装载、ART、ClassLoader 解析或完整 Q08。固定主机测试及双 ABI 构建按证据记录实际覆盖，不宣称所有运行时/分配故障交错已验证。
