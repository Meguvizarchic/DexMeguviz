# 显式方法定义绑定器 v1 草稿

`RuntimeMethodBinder` 是调用方显式调用的 Java 层能力。它接受 `NativeEngine.MethodCandidate` 或完整的 DEX owner/name/prototype，加 initiating ClassLoader 和非空调用方代际对象；空 ClassLoader 表示 bootstrap loader。它不打开来源、执行查询、缓存绑定或追踪之后动态加载的 DEX。已有候选的 source/input/slot/occurrence 原样附在结果上，仅为静态输入身份，并不证明实际类来源。

方法限定于 owner 的 **声明方法**；以请求 loader 非初始化加载 owner 和签名各类型，逐一比较实际参数与返回 `Class` 身份，完整区分重载与协变返回的 bridge。来自 `MethodCandidate` 时比较 DEX 原始 static 位与实际反射 static/instance，冲突返回 `INVOCATION_MISMATCH` 且不暴露 Method；descriptor-only 没有静态来源 flags，预期调用性质为 `UNKNOWN`，结果单独报告实际性质。`BOUND` 证明本次声明类/签名匹配且候选存在时调用性质匹配，不验证其他 DEX flags 与 ART 反射 flags 的等价，不推断虚调用分派、业务 ABI、候选唯一性、签名一致性之外的类型关系或来源真实性。构造器和 `<clinit>` 显式 Unsupported；不隐式上溯父类或修改成员可访问性。

结果保留 initiating loader、实际 declaring Class 和 defining loader（`definingLoaderKnown=true` 且为 null 表示 bootstrap；无法观察时 known=false 并返回 REFLECTION_ERROR）、状态和调用者提供的进程内 generation 引用，`isForGeneration` 仅按对象身份比较，不能侦测 loader 变化或证明后续绑定仍有效；引用持有对象直至结果释放。结果的字段引用固定，但 Method、ClassLoader 与 generation 对象可能由调用方改变；此结果不防止或检测这些变化，也不保证调用者之后使用的成员可访问性或代际仍相同。token 不应序列化或当成来源内容标识。Origin 恒为 `UNVERIFIED`，没有真实性证明路径。来源扩张或 loader 代际变化之后应由调用方重新评估，并保留此前结果实际身份；本接口不设负缓存。

显式调用可能执行自定义 ClassLoader 的代码，反射也可能加载/链接签名中类型；它不请求初始化 owner 或签名类，不构造、调用目标方法、不读取字段，也不修改可访问性。初始化策略不等于零副作用，必须由调用者决定是否信任 loader。输入若缺失、格式无效或超限明确拒绝；找不到 owner、找不到签名类型、签名不匹配、歧义、加载器/反射异常分别用状态表示，不把任何失败说成整个应用不存在。defining loader 获取出现权限异常时不会在错误构造中再次查询，返回 REFLECTION_ERROR；内存耗尽和其他未捕获 Error 可传播；JVM 枚举声明方法会分配，不提供 RSS/时间上界。

descriptor 最长 65535 UTF-16 码元、最多255参数、最多255维数组；只支持 DEX 方法格式，参数不能是void且返回可void，缺失投影返回 INVALID_INPUT。高 Unicode 类名是否可由目标 VM 加载由实际 ClassLoader 决定。两个同名不同 loader 类不得合并；父委派保留 initiating 和 defining 两个身份。所有状态和行为均为内部演进中 API，不承诺稳定 ABI 或 Android/ART 的验收。
