# 内部使用事实扫描器 v1

`src/facts/use_relations/use_scan.hpp` 是内部C++接口，尚未成为QueryIR事实根、公共C ABI或事件Join。扫描范围是调用方提供的一个不可变逻辑DEX及其配套Facts；调用方负责二者同源和source_index在Snapshot中的正确分配。接口不验证外部revision或运行时绑定。

## 值与身份

`collect_uses` 按Facts.methods顺序扫描指定的 `string_use`、`invoke_site` 或 `field_use`。事件以 `(source_index, kind, caller_ordinal, dex_pc)` 标识，PC为DEX code unit；同一调用者在不同PC引用同一目标时仍为不同事件。

`UseRecord` 按值保存caller method_ref、code_offset、opcode、target_index及target_domain。字符串对应string_value，字段对应field_ref；普通调用对应method_ref，多态调用对应method_and_proto并保留extra_proto，custom对应call_site。非多态的extra_proto为UINT32_MAX。custom仅保留原始引用，当前不解析bootstrap。

单次结果使用调用方提供的PMR内存资源。记录不引用方法临时事实vector，释放输入bytes和Facts后仍可读；资源必须活到结果释放。此承诺不意味着已实现Result/Batch公开事实接口。

## 完成与预算

每个有body的方法以相应demand调用既有checked `collect_method`；方法的整个指令流及现有异常边界检查完成后，才将该方法的事件加入临时结果。扫描器只有在声明范围所有方法完成后返回Result；后续损坏、取消、额度或分配失败不会返回部分Result。无body计为已完成但不解码；未请求事实与空事实不是同一状态。

`max_records`限制中间事件总数，默认100000；`max_work`默认100000000，工作量为每次开始的方法1、成功collector的validation_work、每次写入事件1。两者为0或资源指针为空时返回Invalid；未知UseKind返回Unsupported。超出额度返回UseScanError::budget。原有DecodeError（含Corrupt、Unsupported、Cancelled、Budget及PC/偏移）和bad_alloc不转换为空结果；外层取消也可产生UseScanError::cancelled。

Progress的total_methods是声明范围总量，attempted_methods包含已经开始但失败的方法。visited_methods、no_body_methods、decoded_methods、emitted_events、code_units及validation_work只计完整完成的方法。work_units还包含可观察到的未完成方法成本；若底层decoder抛错，其内部未完成工作无法由现有接口精确读取，不作估计。失败时这些统计只是局部诊断，不代表已发布或完整结果。

## 验收边界

固定结构夹具覆盖同caller两个PC、字段读写、普通与jumbo字符串、polymorphic与custom引用域、有效事件之后的损坏opcode、空方法目录、无body、取消、预算、分配失败及输入释放后的值保活。原始字节和checksum由独立Python夹具生成器核对。

扫描器本身不连接事件到caller或目标，不对外暴露事件PC；后续需完成tagged结果／binding／link、按整个计划标记混合计数域、旧getter的Unsupported边界及C ABI异常／deadline映射，才能开放事实根。BoundedExpand、ART、ClassLoader、Hook、设备与性能另行验收。

## v9 显式扩展

默认 use-scan 行为不变。use-stream-v9 的内部 hooks 在一个方法完整 checked、事件与累计进度均已提交后调用；若后续方法失败，已交付的早期 Batch 保留。scanner未合并工作与上层谓词工作共同受同一个剩余工作额度约束，callback 抛错和分配失败不得转成成功空结果。版本语义及限制见 [use-stream-v9.md](use-stream-v9.md)。
