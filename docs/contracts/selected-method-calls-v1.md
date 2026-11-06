# 指定方法完整调用事实 v1

`dmg_snapshot_collect_method_calls_v1(snapshot, source_index, method_ref, options, out, error)`通过现有method_definition_by_ref目录定位本地定义，只对该方法运行checked collector。快照创建已做元数据读取，本调用不重新扫描其他方法体。外部ref无本地定义返回Unsupported；native/abstract本地定义返回明确has_body=false、checked=false且空列表，不能由此推断运行时无调用。

成功句柄只在完整收集和复制后发布，info含snapshot、source、ordinal/ref、code_offset、body/checked、code_units、count、validation_work。事件保留PC顺序及重复、普通/多态/动态调用域、目标索引和extraProto。普通/多态返回复制UTF16 owner/name/声明prototype，多态另返回extra_prototype；call_site保持事件但无虚构方法descriptor。caller/source getter与info分开，来源仍非运行时认证。

options必须版本1和精确size，reserved=0，max_records为1..100000，max_work为1..100000000，deadline_after_ms为0..86400000（0无额外deadline）。max_work约束decoder validation；max_records限制成功发布行数，解码仍受Engine owned预算而非保证只分配max_records项。文本复制受Engine预算及协作deadline检查；调用方应后台执行，不把此同步入口当可强制抢占的Job。

失败out=NULL，不发布成功半成品。返回句柄retain/release持有Dataset/Engine和复制文本，Snapshot/Engine外层句柄释放后仍可读；getter严格size/索引失败不写out。跨source的同ref不得混用，方法调用不代表实际ClassLoader/虚分派。显式041 snapshot可走已有041 method collector；默认入口仍拒041，具体041模式未在本轮专项验证。

本轮Release及真实C连通：2条调用、外部ref拒绝、发布上限拒绝、释放源句柄后读取。特殊域/no-body/完整错误size/并发/取消/Android等留待统一专项。
