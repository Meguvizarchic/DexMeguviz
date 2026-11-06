# Kotlin v4 调用点单扫描

`InvokeSiteQuery` 类型化构造一个 `invoke_sites` 单扫描，复用 `UseEventPredicate` 的 caller 名称、owner、PC、opcode、目标域和布尔组合；事件来自已检查 DEX，普通、polymorphic、custom 均保持各自引用域。事件谓词必须适用于方法调用，文本仍按 UTF-16 编码。它不按 owner/name 推断方法唯一性，调用者若需精确声明仍需依据来源、method_ref、prototype 等实际结果核验。

`TypedInvokeSiteExecution` 复用既有同步 v4 JNI 桥；结果保留来源、PC、target domain 和 extra proto，scope 未声明完整，显式 scope 和 Job 仍不由本类型提供。JSON 64KiB 与原有 native/JNI 资源限制继续生效。宿主提供 Kotlin 2.4.21；不改变旧类型、默认查询或 BIL。该静态事实不代表运行时绑定、ART或完整业务验收。

独立 `ScopedInvokeSiteQuery` 及 `ScopedUseGraphExecution` 可显式声明顶层静态 slot 范围，详见 [scoped v4 合同](jni-use-graph-scoped-v4.md)；本文件中的旧 `InvokeSiteQuery`/入口行为不变。
