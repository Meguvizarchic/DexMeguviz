# 独立元数据证据复核

`verify.py` 从原始 DEX 字节重新解析字符串/类型/原型/方法表和完整 class_data 方法定义集合，不读取引擎缓存，也不导入语料生成器。验证查询返回的实际 `method_index/access_flags/declaration_offset/code_offset/owner/name/prototype/source_sha256`，根据独立匹配集合复核完整枚举、存在性、唯一性和不存在性。Partial 唯一候选不能证明 Unique；两个经过复核的不同候选可证明不唯一。

调用接口：

```python
parsed = parse_dex(path_or_bytes)
expected_matches = select_methods(parsed, query_json)
report = verify_result(path_or_bytes, actual_cli_result_json, query_json)
```

CLI：

```powershell
python tools/evidence_verifier/verify.py --self-test tests/fixtures
python tools/evidence_verifier/verify.py --dex tests/fixtures/generated/metadata-035.dex --query query.json --result actual-result.json
```

此工具只复核 `raw-dex-metadata-v0` 支持的查询和元数据，不是全功能 DEX verifier。它核对文件 SHA-1/Adler32/SHA-256 与相关结构；不验证 opcode、控制流、ART 可装载性、运行时绑定、APK 解包或线程/取消行为。Python 路径和 C++ 路径共享格式规范与人工语义期望，不共享解析实现；这不替代后续 dexq/ART 等第三方路径对照。
