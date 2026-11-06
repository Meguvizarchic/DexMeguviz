# Android 输入范围内的同步 opcode 查询 v1

`ScopedOpcodeQuery.execute` 是显式入口，接受已有 `NativeEngine.Snapshot` 或 `SourceSetSnapshot` 和 UTF-8 QueryIR JSON；必须是直接 `query:v23` 且明确提供 `scope:{slots:[...]}`。未提供 scope、其他profile、未知输入slot、重复slot或超过既有JSON/结果/work上限明确失败；原 `OpcodeQuery.execute` 仍拒绝显式scope，`ScopedMethodQuery` 仍只接受 v1，旧行为不变。

scope 选择调用方提供的输入slot，不是展开后的DEX序号。多DEX APK选择其中所有DEX，资源-only slot产生零来源；slot列表按编译器规范顺序，source indices按快照来源顺序。`Result.query` 的coverage/decision只针对该静态子集；`Result.scope` 返回所声明slot和选中source indices，二者均为复制值，可以在快照关闭后读取。`snapshotScopeComplete` 和 `sourceScopeAuthenticated` 恒为false，不证明已安装包、整个应用、ClassLoader、代码加载范围或APK签名；选中索引不代表所有来源已扫描。

JNI在快照监视器内编译并检查v23能力、work和结果上限，按输入元数据核对slot，再将返回结果的范围索引与预计算范围逐项比对；错误不发布部分Java结果。操作同步且不提供Job/取消接口；现有v23 opcode值与显式通配、signed16规则不变。不得把主机自建样本、声明scope或一次局部结果描述为DexKit全量等价、ART验证或性能优势。
