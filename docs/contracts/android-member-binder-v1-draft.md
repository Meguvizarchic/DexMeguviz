# 显式构造器、字段和 owner 绑定器 v1 草稿

`RuntimeMemberBinder` 仅由调用方显式调用，不缓存，不读取字段、不执行方法/构造器、不改变可访问性，也不主动初始化类。`Class.forName(...,false,loader)`、反射和类型解析仍可能执行自定义 ClassLoader 代码或加载/链接类型；调用方负责决定是否信任该 loader。仅 `BOUND` 意味着本次声明成员及完整静态签名 Class 身份匹配，不证明业务 ABI 或来源；`OWNER_ONLY` 只说明 owner Class 可加载，其 `memberVerified=false`、constructor/field 为空，不证明运行时包含任何构造器或初始化器。所有结果 Origin 恒为 `UNVERIFIED`。

- `bindConstructor` 接受 method_defs `<init>(...)V`；`bindConstructorDescriptor` 接受同形状的描述符，无候选时预期调用性质 UNKNOWN。只检查声明类自身的构造器，比较各参数 Class 身份，不构造对象；候选 raw static 位若与构造器的实例性质不一致返回 `INVOCATION_MISMATCH` 并不交付构造器。`<clinit>` 不可作为构造器。
- `bindField` 只接受实体 `field_defs`（relation=2），引用表不能静默当定义；name、owner、type 是必需投影，flags 若缺失则静态/实例预期 UNKNOWN。枚举 owner 的声明字段，以名称和完整类型 Class 身份同时过滤；raw static 位已知时与实际 static/instance 不同返回 `INVOCATION_MISMATCH`、不交付 Field。`bindFieldDescriptor` 的 expectedStatic 可显式为 null（未知），不会读取字段值。
- `bindClass` 只接受 `class_defs`，要求 descriptor 投影；`bindOwnerDescriptor` 不含静态来源；`bindOwnerAnchor` 只接受静态 `<clinit>()V` 或实例 `<init>(...)V` 候选，检查的是输入结构，随后只解析 owner，不验证该成员在运行时存在。`<clinit>` 绝不伪造为 Java Method。

结果分别记录 initiating loader、声明 Class、defining loader 和 `definingLoaderKnown`（true/null 是 bootstrap，false/null 是无法观察）；权限或运行时安全异常为 REFLECTION_ERROR，不能交付成员。Class/Field/Constructor/loader/token 引用虽然字段固定但对象可变，`isForGeneration` 仅按调用方给的进程内对象身份比较，不检测 loader 变化、不支持持久化 generation token、不证明 origin。静态 source/input/slot/occurrence 只复述输入，不可当真实 loader 来源认证。Scope completeness、唯一性、运行时派发、类层次或 BIL 后验一概不由 binder 推断。

与 `RuntimeMethodBinder` 共用其内部有界 DEX descriptor 解析（最长65535 UTF-16 码元、最多255参数和255维数组）；相关方法仅放宽为包内可访问，既有方法 binder 的公开签名/行为不变。缺成员、目标类型找不到、loader异常、权限失败或歧义均保守返回对应状态；OOM和其他未捕获 Error 可传播，JVM 枚举声明成员不提供总RSS或时间上界。无新增运行时依赖。

固定主机测试可说明明确样本的静态签名绑定，不是 Android/ART、真实BIL、完整DEX verifier 或 SourceSet来源认证。实际构造、字段读取、单例和 `toString` 等业务验证应由外部单独显式 opt-in，不作为本接口的默认行为。
