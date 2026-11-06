# 选定方法参数静态事实 v1

`include/dexmeguviz/method_parameters_v1.h` 提供独立C ABI：`dmg_snapshot_get_method_parameters_v1(snapshot, source_index, method_ref, options, ...)` 在同一已打开snapshot的单个DEX occurrence内读取已检查的方法引用原型及该定义的debug参数名。输入是方法引用索引，不是全局ID或跨来源ordinal；`get_source`/`get_info` 保留当前来源、方法ref和snapshot身份。无本地定义的外部引用仍可取得静态原型参数和返回类型，但不能推断目标的定义或运行时分派。

按原型顺序返回每个参数的类型descriptor及其type_id、参数ordinal，以及debug名称状态：`UNKNOWN`表示没有可用debug名称（包括外部引用、无body或无debug信息），`NO_INDEX`表示存在debug参数表但该条目编码为NO_INDEX，`PRESENT`表示真实string_id，名称按原始UTF-16码元复制。`UNKNOWN` 与 `NO_INDEX` 的name指针为null；`PRESENT` 使用name_state判断存在，即便实际字符串为空也不能按指针或长度猜测缺失。返回类型也按UTF-16值复制；未用 `this` 作为额外参数，long/double各占一个原型参数。

info的debug状态区分 `NO_DEFINITION`、`NO_BODY`、`NOT_PRESENT`、`PRESENT`；外部引用的method_ordinal为UINT32_MAX。方法体的debug_info偏移非零时，该入口有界读取line_start、参数数和uleb128p1名称；若参数数与原型不等，或引用越界/截断，返回CorruptInput并且out为null。它不从局部变量表猜参数名，也不把debug名当作Java反射参数名的保证。原始snapshot的metadata读取和其他API不因未调用此入口而收紧；没有重新验证完整debug程序、指令、ART或加载来源。

options要求精确struct_size/ABI版本、`max_parameters` 1–65536、`max_text_units` 1–1048576、`max_work` 1–100000000、`deadline_after_ms` 0–86400000、reserved为0。文本额度累计返回类型、每个参数类型和每个存在的名称，工作额包含参数、debug头字节和复制的UTF-16单元；超限返回BudgetExceeded、不发布部分句柄。同步deadline由steady clock协作检查，不保证外部分配/系统调用硬实时，且不提供外部cancel。

结果由Engine的control/result PMR计账并保留Dataset；调用方持有snapshot引用直至同步返回，此后可关闭/释放snapshot，结果及其借用指针在最后一次release前有效。所有getter按精确out_size检查，失败不写输出；retain/release与原C ABI句柄合同相同。仅支持标准035/037/038/039/040；实验041返回Unsupported。核心 `dmg_capabilities()` 的 `method-parameters-static-v1` 标记仅声明C核心能力；Android Java/Kotlin/JNI封装范围以独立合同及实际同源产物为准。没有新增依赖、BIL枚举或Android平台类型；Android同步Java/Kotlin封装及其独立范围见 [jni-method-parameters-v1](jni-method-parameters-v1.md)；这不构成Android/ART/反射、完整DexKit兼容或性能结论。
