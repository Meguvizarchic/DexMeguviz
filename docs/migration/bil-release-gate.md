# DexKit 全面退出与超越验收门槛

**目标尚未完成。** DexMeguviz 的通用能力、真实性能和兼容性需经证据证明优于 DexKit，BIL 是第一使用方；删除一个 Maven 坐标或取得构建通过都不是目标完成。当前可选接线默认关闭；33 条规则中有 22 条候选业务守卫，另 11 条未完成守卫，生产启用为 0。所有规则的完整候选袋及业务语义等价、无 DexKit BIL 接线、真实设备和性能均尚未验收。

## 1. 通用语义与来源

- 在无 BIL、Android 业务枚举依赖的核心和独立 CLI 中完成原定 DEX/SourceSet、查询、引用与定义、证据、生命周期及失败语义；对真实语料和有标签的开放/自建样本建立可复算的独立对照。超出 DexKit 的功能应逐项列输入、结果、边界和有效使用方，不能以 API 名称数替代有效能力。
- 33 条 BIL 查询逐条对当前源码、旧 DexKit、C 的原始候选顺序/重复、方法/类/relatedClasses、角色配对、基数、特殊调用、32/128 上限、失败/unknown、direct/cache优先和副作用调用时机做正例、近似反例和不完整对照。画质有 1 条内建候选守卫，另外 21 条须逐条显式批准后才可使用当前 BIL 业务守卫；余 11 条没有现成守卫。这些防护不证明旧 DexKit 完整候选袋及真实宿主等价，完整业务映射仍未验收。
- base/split、重复 occurrence、动态加载、ClassLoader/代际与强身份必须分开。调用方声称完整或attestor返回true不是独立认证；没有足够来源和绑定证据时保留 Unknown，Partial/异常/取消/预算不得写 MISSING。旧 VersionAdapter 若把任何 unavailable 当 MISSING，须先修改消费者及持久状态协议后才能启用 C_ONLY。

## 2. 彻底移除生产依赖

- 在所有规则与运行时门槛通过后，用不引用 DexKit 的 C_ONLY 或等价正式接入替换 VersionAdapter 中的旧 DexKit engine/attempt guard；删除生产源码中的 `org.luckypray.dexkit` imports、`DexKitBridge` 和 `System.loadLibrary("dexkit")` 调用，并保留完整适配状态、失败恢复和回滚机制。候选中 C_ONLY 仍对未完成抛异常，未适配现有消费者，不能直接作为发布补丁。
- 移除 app production `implementation(libs.dexkit)` 和仅为它保留的 version-catalog 坐标；重新解析全部生产变体的完整直接和传递依赖。DexKit 2.3.0 元数据声明 FlatBuffers、NDK cxx 和 Kotlin runtime 依赖，但这些组件可能被其他功能使用，只有独立依赖图证明不再使用时才能处理。不得移除其他功能仍需的 ABI 或 C++ 运行库。
- 清理/替换生产生成物、规则引用和打包配置；对实际候选的 runtime classpath、DEX/JAR、APK/AAB各 ABI native entry、资源/映射以及 release 与变体分别复核 DexKit 坐标、类和 `libdexkit.so` 不存在。历史 APK 或构建缓存不是当前构建证据，也不应擅自删除。保留基线 A/B 的 DexKit 仅允许隔离测试源集/工件，不能流入生产产物；相关合约与 androidTest 改用隔离基线，不得仅删断言。
- `RoamingCompatHook` 还通过外部包的 `DexHelper` 修补 BiliRoaming 分析，这是跨应用运行时兼容路径，不等于本模块的 Maven 依赖。必须逐项确认如何在不依赖该外部 DexKit 流程的目标下保留兼容，不能以移除本模块依赖冒称外部代码也被移除。

## 3. 性能与兼容性

- 同一物理设备、同一不可变 APK/base/split、同一规则/实际业务验真与资源预算下比较 A（真实现有共享 DexKit 会话）、B（语义一致的合理优化 DexKit）和 C；不得按规则重建 DexKit bridge、禁用真实快路径或人为放慢A/B。记录构建/代码/包/设备身份，按 `benchmarks/protocol.v1.json` 预登记顺序、冷/暖、原始配对和排除规则。
- 计入来源读取/哈希、扫描/建索引、JNI、候选物化与业务验真，分别记录全任务延迟分布、CPU、峰值RSS/PSS、托管内存、I/O、残留和前台/尾部影响。以完整正确性为前置，报告 A-B、A-C、B-C 及各规则；不得用桌面一次性结果替代设备或用局部热查询替代全任务。预登记的相对阈值只是最小统计门槛，不能把单一内存路线或人为改变工作量宣称满足用户的整体性能超越要求。
- 在有代表性的已确认宿主版本、不同设备/ABI/页大小及异常/低资源条件上验证实际加载、ClassLoader来源、33项业务角色、重启/缓存恢复、Hook/UI和回滚；每项记录通过、失败或未执行。真实部署、设备与对外发布按实际会话授权进行；静态 AAR、host JVM/JNI、构建和模拟样本均不能替代。
