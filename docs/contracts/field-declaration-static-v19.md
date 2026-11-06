# 所选静态来源内的字段声明候选 v19（隔离候选）

显式 capability `field_declaration_static` 与 `query:v19`，支持单个 `field_uses` scan，或 `method_defs` 左 scan 与 `field_uses` 右 scan 的顶层 `caller` Join/SemiJoin；须使用共同的非空显式 slot、无排序／TopN，否定或将新谓词置于 any 下均拒绝。`target_field_declaration` 接受 `scope` 为 `declared`、`inherited`、`any`，以及可选 owner/name/type 文本 matcher 和 raw flags_contains；此 scope 相对于字段引用的 owner，不是方法 caller 的 owner。允许用普通 pc/opcode/caller 谓词作交集。非所选来源中的定义不可作为确定事实；找不到、重复定义、环、静态／实例冲突、缺失前置接口或不支持的接口边为 Unknown；资源、取消或损坏不是成功空结果。

按引用的完整名称与类型，先查所选 scope 中唯一 owner 的声明；再顺序查直接接口及其超接口；最后查超类。接口成员若非 public static final、可见位冲突，或空接口查找需要沿 DEX 的 superclass 边继续，保守 Unknown；这会把部分合法空接口图标为 Unknown。命中最先声明后才比较指令的 static/instance，冲突为 Unknown。每次只在静态 snapshot 候选中查找，不证明 ClassLoader、访问权限、hidden API 或 ART。对于接口和超类没有完整语义证明的情况不推断不存在。

获得确定命中时，保留 use 的 caller、PC、opcode，以及逐项版本化 `dmg_field_declaration_witness_v1`：item 0 是沿 root/interface/superclass 的 class occurrence 和 path index，item 1 是终点 field_defs occurrence、索引和 raw flags。各项仅是该执行器对选定 QueryID/snapshot/scope 的静态证明，可独立检查原始 DEX 验证；不声称运行时解析。既有普通 witness 与 relation-witness getter 对新增证明种类返回 Unsupported。CLI 输出 `field_declaration` 项；专用 JNI v19 入口使用独立 wire，旧 JNI 入口拒绝。Kotlin 构造器支持读／写筛选与 caller 自选 scope。C、CLI、JNI 仅经实际测试证据说明；Job 不开放 v19 的流式早发，必须先完整计算后原子提交。

Kotlin 构造器接受 `maxResults` 最大 100000 和正数 `maxWork`；专用 JNI 执行入口当前上限分别为 4096 和 100000000。构造成功不代表一定能执行；超过 JNI 上限时执行返回 `BudgetExceeded`。该限制不改变 C 或 CLI 的各自资源合同。

缺失定义、重复定义及环仅在字段查找实际访问到相应节点时导致 Unknown。若引用 owner 自身已找到匹配声明，查找会在访问后续接口或父类前结束；未访问的缺失、环或其他坏边不影响该静态候选，也不因此证明整个类图合法、可链接或能被 ART 装载。

caller Join 的每条结果包含左侧方法、右侧一条字段使用事件及对应声明路径；同方法不同 PC 的事件保持不同 bag 行。SemiJoin 每个方法只保留一个确定右事件及其声明路径作为存在证明，不声称列出了全部事件；确定匹配支配同 caller 的其他 Unknown。未匹配且右侧存在潜在匹配时为 Unknown。所有方法/事件通过 source occurrence 和方法定义 ordinal 精确关联。输出的 declared/inherited 仍相对 field_ref.owner，不推断相对 caller 的字段归属。仅两个根 scan、左方法元数据条件；局部 scope、反向连接、嵌套图及高级 profile 保持 Unsupported。既有 v19 单 scan QueryID 不变。

C Job 在完整标量求值后才进入批次交付，但物化或发布中仍可能取消、失败或遇 ResultLimit；先前交付的 batch 为 provisional，须检查最终 v2 状态。JNI 的专用同步入口沿用 v19 单路径 wire，当前每行只容纳一个右事件的声明路径，不支持多事件路径合并。相关 Kotlin caller 构造器遵循同样的 JNI 4096 结果／100000000 work 上限。
