<div align="center">

<img src="docs/brand/DexMeguviz.svg" width="96" height="96" alt="DexMeguviz">

# DexMeguviz

**独立 C++20 DEX 查询工程（公开脱敏副本）**

C ABI · 桌面 CLI · Android Java / Kotlin 绑定

<br>

[![License](https://img.shields.io/badge/license-Apache--2.0-00AEEC?style=flat-square&labelColor=2d3a55)](LICENSE)
[![Language](https://img.shields.io/badge/lang-C%2B%2B-DEA584?style=flat-square&labelColor=2d3a55)](https://github.com/Meguvizarchic/DexMeguviz)
[![Issues](https://img.shields.io/github/issues/Meguvizarchic/DexMeguviz?style=flat-square&labelColor=2d3a55)](https://github.com/Meguvizarchic/DexMeguviz/issues)

[构建与入口](#构建与入口) · [通用接口补充](#通用接口补充) · [使用约定](#使用约定)

</div>

---

<details>
<summary><b>目录</b></summary>

- [构建与入口](#构建与入口)
- [通用接口补充](#通用接口补充)
- [使用约定](#使用约定)

</details>

---

> **公开脱敏副本**：本仓库由本地开发工作区按白名单导出，仅含源码、契约与状态文档、
> 构建脚本、品牌图标和合规第三方源码。原始运行证据（`work/`、`build/`、`docs/evidence/`）、
> BIL 集成代码、工程包附件与测试二进制夹具**未公开**；文档里对这些本地路径或证据的引用
> 只表示本机可追溯，不代表公开可复验。清洗规则、排除清单与逐文件哈希见
> [SANITIZATION.md](SANITIZATION.md)。本项目采用 Apache-2.0 许可证
> （[LICENSE](LICENSE) / [NOTICE](NOTICE)），第三方组件见
> [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)。

正在开发的独立C++20 DEX查询工程，提供C ABI、桌面命令行和Android Java/Kotlin接口。当前源码已包括有序raw DEX/APK来源、七类实体、按需指令事实、关系与有界展开、Job/取消、可选桌面SQL、持久事实缓存和离线候选包。完整SDK验收与真实BIL替换尚未完成。

当前能力及各使用方的支持形状见[支持矩阵](docs/support-matrix.md)，逐项任务见[backlog.json](backlog.json)，最近状态见[PROJECT_STATUS.json](PROJECT_STATUS.json)。不要用早期保存的AAR代表当前源码，也不要把主机编译或静态候选当设备/Hook/业务验收。

## 构建与入口

从[源码入门](docs/getting-started.md)开始。已有Python 3、CMake≥3.25和C++20工具链时，可用项目脚本构建host；Windows脚本发现本地Visual Studio工具，不安装依赖。

```text
python tools/build_host.py --preset host-debug
build/host-debug/dexmeguviz.exe inspect tests/fixtures/generated/minimal.dex --json
build/host-debug/dexmeguviz.exe explain --query tests/fixtures/queries/method_exact.json --json
python -B tools/dexmeguviz.py --help
```

桌面SQL、持久缓存、结构排序/dataflow及实验041工具均有显式构建开关；Android库不引入SQLite。AAR源码入口为bindings/android，宿主自行提供Kotlin标准库2.4.21，库不打包或传递该运行时依赖。可选sample用自建DEX演示查询，不扫描其他应用；一台设备已运行过较早版本的固定样本，当前接口、完整设备与ART验收仍待完成。

## 通用接口补充

- 按来源读取字符串、类型、字段/方法引用和原型描述符见[来源符号](docs/contracts/source-symbol-text-v1.md)及[成员引用](docs/contracts/source-member-ref-v1.md)；结果是静态 DEX 索引，不认证运行时绑定。
- 选定方法事实、参数和静态注解分别见[方法事实](docs/contracts/jni-method-facts-v1.md)、[方法参数](docs/contracts/jni-method-parameters-v1.md)和[注解](docs/contracts/jni-annotations-v1.md)；注解值结构可使用[有界解码](docs/contracts/encoded-value-v1.md)。
- 显式方法 opcode 序列查询见[v23 合同](docs/contracts/opcode-sequence-v23.md)；Android提供同步、非范围异步Job及独立显式输入槽子范围入口；范围Job和完整 DexKit matcher 语义仍未完成。异步入口待组合AAR验证。

## 使用约定

- 引用、定义、来源出现、snapshot与运行时绑定分别表示；同字节的不同occurrence不自动合并。
- coverage与decision分开。Partial/Unknown/限额失败不能当作不存在或唯一性证明；完整性只针对明确声明的静态范围。
- 查询版本/能力显式门控；不支持的组合返回Unsupported。静态反射、继承、关系和结构分析不替代ART或业务验真。
- Query/Result/Job/Batch、复制/借用来源及缓冲生命期遵循各版本合同。数据预算、逻辑work与RSS/壁钟不是同一指标。
- 指定方法调用接口只读取已选caller；它不证明整个APK候选完整，也不证明ClassLoader来源。
- BIL静态计划已有33项，但统一业务执行/L0桥已接源码、仍待完整验收，不能据此宣称已替换生产DexKit。

原始工程资料与哈希保留在references/engineering-pack，属于需求材料而非外部发布或设备操作授权。依赖固定为已批准的miniz 3.1.2（MIT）、可选桌面SQLite 3.54.1（Public Domain）；来源和许可见third_party及THIRD_PARTY_NOTICES。项目分发许可、公开坐标和发布仍需单独确定。
