# Result 与证据契约

现行结果profile为`dex-method-metadata-v1`，JSON schema_version=1；原raw-dex-metadata-v0是bootstrap历史profile。API调用返回DMG_OK表示生成了可读取Result，调用者还必须读取execution_status、coverage、decision。新结果包括inputs/sources清单和每行origin，多源时顶层单源摘要字段为null。

| 意图 | 完整零候选 | 完整一个 | 两个不同候选 | 未完成且0/1候选 |
|---|---|---|---|---|
| Unique | ProvenFalse / NoMatch | ProvenTrue / None | ProvenFalse / Ambiguous，可早停 | Undetermined |
| Exists | ProvenFalse / NoMatch | ProvenTrue / Witness，可早停 | 首个已足够 | 有witness为True，否则Undetermined |
| Enumerate | NotApplicable | NotApplicable | NotApplicable | Partial，列表不是完整关系 |

coverage Complete 限于当前 snapshot 的 method_defs 声明遍历，不代表全格式、完整运行时来源或业务验证。Exists/Unique 可以 execution Complete 且 coverage Partial；ResultLimit 返回 execution BudgetExceeded + Partial。失败绝不能写业务完整负缓存。

`visited_methods` 为已访问定义数量，`total_methods` 为已建立的声明目录数量；结果输出保存 source_sha256/content_id/occurrence_id/snapshot_id，candidate 包含 method_index、access_flags、declaration_offset、code_offset、owner/name/prototype。declaration_offset 为 encoded_method 的 method_idx_diff 开始字节，不是 dex_pc。

所有字符串以 JSON UTF-16 转义无损输出。CLI 在 8 MiB 上限内暂存完整 JSON 后提交；输出过限返回错误，不提交半份成功结果。标准输出为机器JSON，诊断到stderr；退出码0执行完成、2输入/能力/来源问题、3资源、4内部错误。退出码0本身不证明完整遍历。

Python 独立 verifier 从原始字节重新读取引用表与完整定义目录，校验输入摘要、每个候选的实际字段、声明偏移与完整性/基数结论；不复读引擎缓存。该独立路径仍只覆盖 metadata 子集，不是ART装载/完整指令验证。

异步Job已分开记录Queued/Running/Completed/Cancelled/Failed、coverage和decision。next返回NotReady只表示等待超时，EndOfStream只在终态且队列排空时成立；调用者必须另读最终status，EOF不吞掉失败。Job产生的Batch一律为provisional，Batch计数是该批行数，最终Job outcome计数是已发布候选总数；在最终成功前不能把多个批次提交为完整结果。
