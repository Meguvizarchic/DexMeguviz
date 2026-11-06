# 多定义静态接口字段查询 v11

`declares_fields.scope="inherited_interfaces_resolved"` 使用 capability 524288、节点 32、见证 11、profile `dex-query-interface-resolved-v11`、规范域 `DexMeguviz:QueryIR:interface-resolved-v11` 和 `query:v11:`。显式 `interface_resolved` 也选择此域。与 v6、v7、v8、v9 或 v10 的谓词和显式能力混用均返回 Unsupported；v5 尚未开放。旧 v8 域与字段含义保持不变。

该静态模型枚举有界世界：每个描述符在一个世界内选择一个可观察定义，同一描述符的重复引用使用同一选择，来源 occurrence 彼此独立。完整世界全部为真或全部为假才产生相应结论；分歧、缺定义、不完整范围、环和不支持的接口或字段形态均为 Unknown。无约束区间为恒真特例。接口根固定为查询选中的本地定义，沿父接口搜索，不构造 Object 父类路径；与固定 superclass 路径冲突的重复定义保守处理。预算和取消沿既有错误机制，不能把不完整世界当成否定。

`dmg_result_get_interface_resolved_witness_v1` 使用现有接口见证布局，旧接口 getter 对 v11 返回 Unsupported，新 getter 对 v8 返回 Unsupported。每世界的节点、边、frontier、字段和 branch 保留来源身份；item 6 记录描述符的定义选择，node 为引用来源节点，aux 为候选数，detail 为该来源 DEX 的 type_ref，source/local 为选中的 class_def。各项目与原始 DEX 一起复核，不代表运行时加载器绑定。

此为静态候选模型。独立原始 DEX oracle 已核对有限场景的节点、边、字段、分支、选择和缺失 frontier，并检查伪造事件；其样本限于单类 DEX、ASCII 字符串及受支持的有向无环完整图，另有一个缺失定义场景。不完整范围、环、复杂访问位、多类 DEX、预算和取消等不在该 oracle 的完整证据覆盖内；尚不能据此证明 ART、完整 DEX verifier 或共享库导出。
