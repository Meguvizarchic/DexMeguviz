# Android 显式输入 slot 的类注解查询

`ScopedClassAnnotationQuery.execute(snapshot, queryJson)` 同步执行直接 v24 `class_defs` 查询，必须明确提供 `scope:{"slots":[...]}`；支持单来源和 SourceSet。`Result.query` 是复制的 `NativeEngine.EntityResult`；`Result.scope` 保存规范顺序的输入 slot 和按快照顺序展开的 source 索引。一个多 DEX APK slot 展开为该输入中的全部 DEX；资源-only slot 可以展开为零来源，空 slot 列表选择零来源。相同 DEX 字节在不同 occurrence 不合并。

coverage 和 decision 只针对所选静态输入；Unknown 元素保留在 `unknownRows`，不能把零候选当成已证实不存在。Scope 的 `snapshotScopeComplete`、`sourceScopeAuthenticated` 始终为 false；所选来源不证明设备安装、完整应用、签名或 ClassLoader，索引也不保证实际全部扫描。复制结果在 snapshot 关闭后仍可读取。

桥接复用已编译查询的版本化只读 slot getter，按输入元数据展开并与执行结果的 scope source 索引逐项核对；每条候选的来源还必须属于所选集合。未知 slot、重复 slot、无显式 scope、非 v24、非法形状或预算超限明确拒绝。原 `ClassAnnotationQuery` 继续拒绝 scope。`start` 提供显式范围 EntityJob；缺省元素 Unknown 和核心其他边界见 `docs/contracts/class-annotation-query-v24.md`。

仅声明本次固定 Windows JNI Java/Kotlin 主机样本及类文件/keep/导出核对范围；不能据此声称 Android/ART、设备或性能验收。
