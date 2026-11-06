# 独立 DEX 语料

`generators/generate_dex.py` 仅使用 Python 标准库，独立于 C++ 引擎生成 035/037/038/039/040 原始 DEX。正常语料定义抽象类 `Lsample/Example;`，包含 `public abstract locate()V` 和 `public static native second()V`；`Ljava/lang/Object;->external()V` 仅为引用，不是定义。字符串包含中文、补充平面字符和嵌入 NUL，按 UTF-16 单元排序，以 MUTF-8 存储。

正常文件包含 SHA-1、Adler32、排序 ID 表、class_data 及按偏移排序的 map；没有 code_item，因此不构成指令解码、Android 装载或 APK 支持证据。错误语料覆盖截断、偏移/索引越界、ULEB 溢出、MUTF 长度/编码错误、重复定义和 class_data/string_data 内部伪造项引用；041 和反向字节序用于明确 unsupported 边界。

```powershell
python tests/fixtures/generators/generate_dex.py
python tools/evidence_verifier/verify.py --self-test tests/fixtures
```

`expected.json` 的语义由生成器中的人工模型声明，偏移由布局构建时记账；不读取引擎输出。`manifest.json` 固定每个文件的 SHA-256。`queries/declaration-cases.json` 是当前声明查询的独立期望，尚不覆盖计划 Q01–Q12 的完整 QueryIR。

使用事实语料由 `generators/use_relations.py` 从固定的 `generated/method_facts/method-uses.dex` 生成。它覆盖同一调用目标的不同 PC、字段读写、普通／jumbo 字符串及有效事件后的损坏 opcode，附独立原始字节和校验和自检。重建时必须指定不存在的新输出目录，生成器不会覆盖或删除既有目录，例如：

```powershell
python tests/fixtures/generators/use_relations.py --source tests/fixtures/generated/method_facts/method-uses.dex --output work/use-relations-rebuild
```

这些是结构性测试样本，不证明 ART 加载或运行时行为。全部语料条目和哈希列在 `catalog.json`；重建目录清单的脚本是 `tools/catalog_fixtures.py`。

语料和生成代码由本工程新建，当前仅用于本地开发；分发许可待项目所有者决定。provenance 标记为 `Project-original; distribution license pending owner decision`。格式依据：[AOSP DEX format](https://source.android.com/docs/core/runtime/dex-format)。未复制 AOSP 实现代码。

`unique-one-v12` 是单独的 UTF-16 使用样本套件，`generators/unique_one_utf16.py --source generated/use_relations/string-normal-jumbo.dex --output <新目录>` 从固定哈希原样本生成 DEX 与 manifest；catalog 不将其归属给 use-relations 生成器。其静态指令证据不证明 ART 行为。
