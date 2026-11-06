# JNI 方法计划流式会话草案

`NativeEngine.openMethodStream(queries, maxSourceBytes, maxOwnedBytes)` 在一个核心 Engine 中编译 1–64 条 method-v1 JSON 查询，之后 `MethodStream.openRawDex(bytes, slot)` 按需打开来源，`queryMethods(snapshot, index)` 重用指定计划；调用方可逐份关闭 Snapshot，无须将全部 DEX 同时驻留。Session、Snapshot 均须显式关闭，Session 关闭不强制关闭已打开的 Snapshot；这些 Snapshot 仍可使用原 `queryMethods(byte[])`，但无法再通过已关闭会话调用已释放的计划。

只接受 direct method-v1、不接受显式 scope 或其他 profile；结果与既有方法桥相同，始终表示不完整来源范围。所有步骤同步且不可取消，最多16个活动/正在创建会话，Snapshot 仍占原有64个全局槽位。`maxSourceBytes` 是单 DEX 来源上限（最多 `Integer.MAX_VALUE`），`maxOwnedBytes` 为该 Engine 的核心记账上限，不覆盖 Java 数组、VM 内存或进程 RSS。调用方须在 `openMethodStream` 预编译返回前保持 `queries` 及其每个 JSON 字节数组不变，打开快照时须在调用返回前保持 DEX 字节数组不变。计划和所有同时打开的快照共享该预算，低预算下的失败与单独 Engine 的内存阈值无需一致。

Session 的打开、查询、关闭同步串行，并在查询时锁住传入的 Snapshot；来自其他 Engine 的 Snapshot 被拒绝。结果是 Java 值副本，关闭来源后依然可读。该接口不证明整个 APK/Loader 来源完整性、ART 映射字节或业务行为，不声称压缩包自动发现、反射查询复用或普遍性能提升；仅复用会话不等于多个查询共享遍历。

`MethodStream.queryMethodsBatch(snapshot, queryIndices, cacheBytes, maxCacheWork)` 选择 1–32 个已预编译计划并一次执行，结果顺序及重复索引与输入一致。此接口先按现有 `MethodBatchQuery` 的 capability、demand 和 projection 子集准入，超出子集的计划明确拒绝；准入后建议核心启用直接 method-v1 枚举的单遍外层遍历，不满足融合形态的计划由核心整体回退逐条执行。调用方不能仅凭接口名称认定发生融合。每条结果保留自己的查询身份、状态和覆盖信息。批次原子交付；发生编译后执行或物化失败时，抛出的 `MethodBatchQuery.Failure.failureIndex` 是本次索引数组的位置，-1 表示不可归因；不得从失败推断无匹配。单条结果的 ResultLimit 仍需检查 `executionStatus` 与 `reason`。

调用方保持 `queryIndices` 在调用期间不变，规则与快照须属于同一会话；会话和快照锁与单查询一致。缓存与返回值沿 `MethodBatchQuery` 的 16 MiB 缓存、1e8 缓存工作量、总计 4096 候选和 1048576 UTF-16 单元限制；Engine 核心预算由该会话的计划、来源、缓存和结果共享。批量与逐条执行在紧预算下的内存峰值及失败时机可能不同，缓存和多规则遍历不保证一次指令解码或性能收益。此同步接口仍不可取消；反射规则不能通过此桥提交。
