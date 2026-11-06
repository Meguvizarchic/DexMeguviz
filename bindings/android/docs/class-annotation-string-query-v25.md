# Android 类注解字符串查询 v25

`ClassAnnotationStringQuery.execute` 对单来源或 SourceSet 同步执行直接 class_defs v25 查询；`ScopedClassAnnotationStringQuery.execute` 同步执行显式输入 slot 子范围，返回复制的 EntityResult 和规范化 slot/source 索引。`ClassAnnotationStringQuery.startJob` 提供非 scope 的有界 EntityJob，范围 Job 由 `ScopedClassAnnotationStringQuery.start` 独立提供。旧 v24 入口保持拒绝 v25，v25 入口也拒绝 v24、错误 scope 形状和未支持的 profile；两种能力必须同时显式声明。

字符串按每个 DEX 来源局部的 string_id 解读并精确比较 UTF-16。缺少显式元素是 Unknown，必须读取 unknownRows、coverage、decision 与 executionStatus；Job 批次暂定，EOF 不表示成功。多 DEX、重复字节的 occurrence 和资源-only slot 维持静态来源区分。范围只描述调用方选中的输入，不认证签名、ClassLoader 或运行时实际加载；静态范围 Complete 不表示整个应用完整。

输入及输出继承 64 KiB QueryIR、4096 结果、1e8 work 和输出文本限额；Job 继承现有队列、取消、关闭和交付失败合同。核心不支持的关系图、排序、top-n、字段/方法/参数查询及数组/嵌套值匹配均不在此桥的承诺中。无需新增 Kotlin 依赖。

当前证据为固定自建 DEX 的 Windows JNI Java/Kotlin、旧桥回归、类/keep 与原生导出检查；不是完整 AAR、Android/ART、真实设备、生产 BIL、完整替代或性能证据。
