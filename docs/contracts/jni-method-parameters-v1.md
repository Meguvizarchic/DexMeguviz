# Android 方法参数静态事实 v1

`Snapshot.inspectMethodParameters(methodRef, ...)` 和 `SourceSetSnapshot.inspectMethodParameters(sourceIndex, methodRef, ...)` 显式读取一个已打开DEX occurrence的方法引用原型与可用debug参数名；`MethodParametersExecution` 提供相同语义的Kotlin入口。methodRef是该DEX的局部method_id，不能跨来源复用。外部方法引用也能取得参数/返回类型，但不能由此推断定义或运行时绑定。

`MethodParametersResult` 和每个Parameter都是复制值，可在snapshot关闭后读取。debug状态分别为NO_DEFINITION、NO_BODY、NOT_PRESENT、PRESENT；名称状态分别为UNKNOWN、NO_INDEX、PRESENT。UNKNOWN与NO_INDEX的`name`为null但含义不同；PRESENT的名字可以是空字符串，不能用长度判断是否存在。类型descriptor和debug名逐UTF-16码元复制，J/D各为一个原型参数，不包括隐式this。sourceIndex是展开DEX序号，inputIndex是原始输入序号；slot、role、occurrence与snapshot ID保留静态来源身份，不认证APK签名、安装集合或ClassLoader。

调用同步，默认最多4096参数、1048576个UTF-16文本单元和100000000逻辑工作，显式参数可设置1–65536、1–1048576、1–100000000及0–86400000ms截止；越界、损坏或预算失败由NativeFailure/IllegalArgumentException表示，不产生半个可用结果。Java/JNI线格式有8 MiB上限，字符串/记录严格校验；这些限制不等同总RSS或墙钟保证。若debug参数数与方法原型不符，C核心返回CorruptInput，不把它当空列表。实验041保守Unsupported。

旧Snapshot/SourceSet同步方法按实例锁串行，关闭后拒绝后续调用；JNI lookup持有source owner直到复制完成。返回对象没有native句柄，不需要额外close。没有Job/外部取消、完整debug程序/ART验证、Java反射参数名字保证或完整DexKit兼容。标准库版本仍由宿主提供；R8需保留结果类decode及NativeEngine私有native签名。
