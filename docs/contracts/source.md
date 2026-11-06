# Source 契约

当前实现profile为`dex-method-metadata-v1`，有序多来源与现行身份编码以[source-set-v1.md](source-set-v1.md)为准。以下v1身份段保留为bootstrap历史说明，不再作为当前新Snapshot的编码。完整设计见工程计划第4节。

## 历史单来源v1身份（已由Occurrence v2/Snapshot v2替代）

ContentId = `sha256:raw-dex:v1:<decimal byte length>:<lowercase SHA-256 of all owned bytes>`。它是物理内容身份；LogicalDexId 为该 ContentId 加 header offset，当前仅 offset 0。未来 041 必须按完整物理容器建模，不以单逻辑 file_size 截断摘要。

SourceOccurrenceId 为 `occurrence:v1:` 加 SHA-256。输入为 UTF-8/原始 C 字符串字节组成的 `dmg:occurrence:v1:`，依次追加 namespace、slot key、role=`raw-dex`、ContentId；每段用 `<decimal byte length>:<bytes>` 编码，不规范化或去重。它不包含 SnapshotId。

SnapshotId 为 `snapshot:v1:` 加 SHA-256；输入 `dmg:snapshot:metadata-v0:ordered:1:` 加同样 length-prefix 的 namespace、occurrence ID。当前只能打开一个 raw DEX；未来多来源保留显式顺序与 slot，必须升级语义版本。

LocalRefId 是 LogicalDexId + table kind + index；ReferenceId 再加入 occurrence。DefinitionId 是 occurrence + LogicalDexId + class_data 声明字节偏移。方法 index 不可跨 DEX 直接联接；descriptor 相同不合并定义。

## 所有权与准确来源

`dmg_snapshot_open_copy` 在返回前复制输入和选项字符串。调用期间调用者保证指针有效且字节不被并发修改；返回后原 buffer 可释放或修改。snapshot 持有不可变 Source；Result 共享保持 Source，关闭/释放 snapshot 不使既有结果悬空。

复制只冻结取得的字节。未给出与预期一致的expected_sha256时，精确来源revision未验证。CLI的--expected-sha256绑定主INPUT，C API可对各SourceSpec分别绑定；mtime/长度/dup FD不升级此状态。

`dmg_snapshot_open_borrowed`要求不可变lease与成对retain/release callback；callback必须线程安全且不得抛异常。借用区独立计入borrowed_bytes，Result/Batch保持Source直到最后释放。`dmg_snapshot_open_fd`始终复制指定范围并保持原FD位置；Windows用ReOpenFile独立句柄，POSIX用dup+pread。两者均不把复制升级为准确revision，expected_sha256仍单独验证。不提供mmap快路径；APK与多来源使用新增SourceSet入口。

## 限制与验证范围

输入先检查调用者 source byte limit 和固定 16 MiB 上限再复制。Reader 另限 header/map 总项数各 1,000,000、展开列表累计 1,000,000、encoded-value 嵌套最多 1024 层、单字符串 1,048,576 UTF-16 单元、累计文本 16,777,216 单元。系统分配失败返回 OutOfMemory。

Engine现用PMR在实际分配前预留source/facts/scratch/query/result/control分类字节；parser临时和输出容器、SHA输出、句柄及state控制块均纳入，失败回滚。借用地址字节另计上限。保留Batch的费用不会因Job结束归零。根Engine对象、C++运行库诊断、mutex/thread内部状态、线程栈、allocator元数据、CLI缓冲与RSS不属于此managed-bytes预算；每Engine最多64个活动Job，默认4。并发stats是多原子采样，静止时可精确对账，不能宣称事务一致快照。详细契约见execution-v1.md。

验证覆盖header/map/ID tables/class_data、type_list与code_item真实条目起点、try/catch数值边界和类拓扑；encoded_array逐项检查边界、值类型、引用域和注解名称；annotation_item、annotation_set、annotation_set_ref_list与annotations_directory检查条目边界、实际起点、排序、值与引用域以及已关联类的成员归属，未关联目录仅检查结构，参数注解列表长度与方法签名的对应关系尚未验证，也不因长度不等直接判损坏；[固定修订的 ART 参数反射实现](https://android.googlesource.com/platform/art/+/14a814bd94/runtime/native/java_lang_reflect_Parameter.cc) 对某些构造器隐式参数的数量差异有兼容调整，这不构成当前工程已实现对应运行时语义；call_site指向数组起点并检查前三值，method_handle检查类型及引用域；static_values数量不超过本类静态字段数，按字段顺序检查基元编码类型和引用分类，共享数组按每个引用类分别检查并计入预算。debug_info逐条检查有界LEB、操作数引用和终止符，并确保code指向真实条目起点；每个参数名和调试操作码（含结束符）计入全局展开列表预算，超限返回BudgetExceeded；默认metadata-open不检查debug与code或方法的寄存器、参数关联；内部显式 `read_metadata_with_debug_associations` 可按各关联code的registers_size、累积debug地址上限及行号，以及各声明方法的原型参数个数单独检查（J/D各算一个、不计this）；地址恰为insns_size允许，该关联入口未验证指令边界。未关联条目不推断签名或关联边界，此入口尚未通过公共ABI或CLI开放。PC/行号、类型赋值及局部变量生命周期尚未完整验证。仍不能输出完整DexStructureChecked：debug/annotations/encoded-value/call-site/handle语义、指令/CFG和runtime binding未完整验证。默认不验证DEX header Adler-32和SHA-1；调用者可按source occurrence显式调用`dmg_snapshot_check_dex_checksums_v1`或`dmg_result_check_dex_checksums_v1`，CLI可选`--dex-checksums`。两者各自报告预期、实际与匹配状态，不因不匹配自动拒绝或修改查询决策；成功仅表示计算完成。输入字节上限不够时返回BudgetExceeded且不修改输出，接口同步执行、没有取消/deadline、没有缓存。DEX SHA-1仅是格式字段，不代表来源认证；expected SHA-256、ZIP CRC和结构安全仍独立。Archive CRC与header consistency由独立组件报告，不能代替DEX验证。

内部按需 `debug::positions` 在同一已检查 metadata/DEX 快照上，对单个方法执行 checked 指令解码，按 debug 特殊操作码发出的 position 分类为指令起点、指令内部、payload 起点、payload 内部或 code end；中间地址推进不产生 position。该入口设置 opcode/position/解码工作上限并使用调用者 PMR；参数名另有限制至 65536 个，不计入 opcode 上限，解码工作限额不等于总 CPU、分配或 RSS 限额；返回分类而不把 payload 或 code end 自动判为损坏，也不检查 debug 局部变量生命周期、ART 类型或可达性。它不改变默认 metadata-open、公共 ABI 或查询语义；调用者必须提供同一不可变快照，仍不代表完整 verifier。

内部按需 `debug::local_events` 对单方法输出 debug START_LOCAL、START_LOCAL_EXTENDED、END_LOCAL、RESTART_LOCAL 事件，按原始顺序保留 PC、debug 字节偏移、寄存器和原始 uleb128p1 索引（零表示缺省；end/restart 没有索引）。它依赖同一不可变且已通过 metadata 检查的 DEX，按当前 code 的寄存器数与指令总长度校验事件；允许 code-end，不判断 PC 是否为指令起点。每个操作码、事件和 checked 指令解码工作分别受限，参数个数至多 65536 且不计入 opcode 上限，结果使用调用者 PMR；限额不覆盖总 CPU、分配或 RSS。它不推断初始局部变量、局部变量宽度、生命周期合法性或 ART 类型与可达性，不改变默认解析、公共 ABI 或查询语义。失败时不返回部分结果。


显式041容器实验另见 [dex041-experimental-v1](dex041-experimental-v1.md)；上述默认标准入口仍不接受041。

## 标准 DEX 映射段之间的零填充

035/037/038/039/040 的已检查可变长度段，逐项解析和段内真实条目起点、计数、边界仍保持；当下一个 map 段起点晚于已解析段尾时，允许超过最短对齐量的零字节间隙，并逐字节拒绝非零内容，不容忍越界、重叠或缺少被引用的条目。最后一个映射段的既有尾部约束不变；041 实验路径不作更改。间隙的处理不代表完整 ART verifier、指令或运行时合法性。

结构依据：AOSP ART 固定版本 [dex_file_verifier.cc](https://android.googlesource.com/platform/art/+/46c8f60c6cee3b008e27d18412ecb3bc0a2bdb27/libdexfile/dex/dex_file_verifier.cc#2404) 逐项完成当前段后拒绝下段重叠，并按 [CheckPadding](https://android.googlesource.com/platform/art/+/46c8f60c6cee3b008e27d18412ecb3bc0a2bdb27/libdexfile/dex/dex_file_verifier.cc#1002) 检查直到下段起点的零字节；实际ART设备行为仍需独立验证。
