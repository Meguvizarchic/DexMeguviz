# 通用单方法静态事实 v1

`dmg_snapshot_collect_method_facts_v1` 按已打开快照的 source_index 与本地 method_ref 定位一个方法定义，在一个checked指令解码中按显式位掩码收集字符串、字段、数值、调用、类型和指令列表；不依赖BIL或DexKit。索引均属该逻辑DEX，来源与caller另由getter返回；外部ref没有本地定义时返回Unsupported，不把它当空方法。

返回句柄保活Dataset/Engine及复制的UTF-16文本；所有文本指针在句柄release前有效。字符串、字段owner/name/type、方法owner/name/prototype和类型descriptor保留UTF-16单元；调用保留普通method、method-and-proto及call-site域，custom无虚构目标，polymorphic额外原型单列。字段事件保留opcode和PC，不假装完成继承/运行时字段解析。数值保存原编码解读后的32/64位bit pattern、opcode和kind（0常量、1算术字面操作数），不推断应用层整数/浮点类型。指令项包含PC、宽度、opcode及payload_kind；payload单独标记，不应当作可执行opcode。

info的requested_mask区分未请求与已请求空类别；未请求类别的getter返回Unsupported，非法索引/size返回InvalidArgument且不写out。native/abstract本地定义返回has_body=false、instruction_checked=false、空列表；不得把它解释为运行时无调用。请求body后任一解码/限额/取消/分配失败都不发布部分handle。最大聚合返回行数1–100000，decoder work上限1–100000000，deadline为0或不超过86400000毫秒；work是逻辑验证工作，不是CPU/RSS总限额。decoder临时索引与复制值受Engine账本，deadline为协作式而非强制抢占。未请求指令列表时解码验证所需索引在结果物化前释放。

这是checked静态事实，不是ART verifier、控制流、虚分派、安装来源或ClassLoader绑定证明；不自动推断DexKit API级或行为完全兼容。一次解码支持按需收集多类事实，但尚未做同设备DexKit性能对照，不声称更快。
