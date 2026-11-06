# 继承字段谓词与目标符号连接 v18

显式声明 `inherited_fields`、`use_target_symbol` 和 `inherited_target_symbol`（新增能力位 67108864）；关系表达式须同时包含 `declares_fields.scope=inherited` 谓词和使用事实的 `target_symbol` Join/SemiJoin。QueryID 使用 `query:v18:`、规范域 `DexMeguviz:QueryIR:inherited-target-symbol-v18`。缺任一必要能力或谓词、无目标符号连接以及 v8/v11 接口、数值、流式、反射或其他高级能力混用均明确 Unsupported；旧 v6、v16 等计划的身份与语义不变。

继承谓词按所在子树的来源范围解析父类，沿 v6 保留每个来源 occurrence、分支、路径与 Unknown；目标连接按完整 UTF-16 符号保留调用/字段/字符串事件与每个定义或引用的静态匹配。两者不隐式更改各自的来源域或将未知当成缺失；结果的 typed use、关系连接及继承见证分别通过现有 v2 getter 和 `dmg_result_get_inherited_witness` 读取，生命周期沿用原 C ABI。

v18 是受限静态组合，不推断 ClassLoader 绑定或运行时字段/方法分派。同步 JNI `queryUseGraph` 使用私有 wire v2 承载继承路径细节，并支持核心认可的显式 scope；CLI 和 C ABI 也支持。异步 use-graph Job 尚未实现，旧 metadata graph 等其他 JNI 入口仍拒绝该 profile。详见 [JNI use-graph v2](jni-use-graph-v2.md)。不是完整 Q08、完整 QueryIR 或 Android/ART 验收。

当前样本只覆盖固定方法、字段与嵌套字符串关系；执行中取消、所有分配故障、全部图算子组合尚无本 profile 的专项验证。已有共享执行器合同不可据此扩大为完整覆盖。
