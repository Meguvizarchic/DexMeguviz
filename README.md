<p align="center"><img src="docs/brand/DexMeguviz.svg" width="96" height="96" alt="DexMeguviz"></p>

# DexMeguviz

DexMeguviz 是面向 DEX 和 APK 的 C++20 静态查询库，提供 C ABI、桌面命令行工具和 Android Java/Kotlin 绑定。

## 核心能力

- 按声明顺序读取 DEX（035/037/038/039/040）与 APK 来源，检索类、方法、字段、类型、字符串及其引用。
- 按需读取方法体指令、参数、注解与源码调试信息，并执行带深度和预算限制的关系图查询。
- Android 端支持同步查询与可取消的异步任务（`Job`）；桌面端可按需开启 SQLite 查询接口与持久化缓存。

查询结果的完整性以声明的输入范围与预算为准。静态命中仅用于定位字节码中的候选位置，最终运行时绑定与业务校验需由调用方在目标环境中确认，详见 [支持矩阵](docs/support-matrix.md)。

## 快速接入

### Android

通过 Maven Central 添加依赖（也可使用 `io.github.jichuo1.meguviz:meguviz-bom:1.2.0` 统一对齐版本）：

```kotlin
dependencies {
    implementation("io.github.jichuo1.dexmeguviz:dexmeguviz-android:1.2.0")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.4.21")
}
```

该制品支持 Android 8.1 及以上（`minSdk 27`），包含 `arm64-v8a` 与 `armeabi-v7a`，宿主应用需使用 `compileSdk 37.2` 或更高版本，并由宿主自行提供 Kotlin 标准库（`2.4.21`）。详见 [Maven Central](https://repo.maven.apache.org/maven2/io/github/jichuo1/dexmeguviz/dexmeguviz-android/) 与 [Android 构建与查询示例](docs/getting-started.md#android)。

### 桌面与原生项目

使用 CMake `3.25` 或更高版本与 C++20 工具链构建：

```sh
cmake -S . -B build-local -DDMG_BUILD_TESTS=OFF -DDMG_BUILD_FUZZERS=OFF
cmake --build build-local --config Release --target dexmeguviz
```

通过构建生成的 `dexmeguviz` 可执行文件运行 `inspect app.apk --json` 查看输入与 DEX 结构摘要。桌面 SQL、持久化缓存及其他可选工具的开启方式见 [源码接入指南](docs/getting-started.md)。

## 文档与接入工具

- [AI 接入与迁移技能](.agents/skills/dexmeguviz/SKILL.md)：包含工程盘点、模块选型、Java/Kotlin/C ABI 迁移示例及排障指引
- [源码接入指南](docs/getting-started.md) · [支持矩阵](docs/support-matrix.md) · [Android 构建切片](bindings/android/README.md)
- [来源符号与文本](docs/contracts/source-symbol-text-v1.md) · [成员引用](docs/contracts/source-member-ref-v1.md)
- [方法事实](docs/contracts/jni-method-facts-v1.md) · [参数](docs/contracts/jni-method-parameters-v1.md) · [注解](docs/contracts/jni-annotations-v1.md)
- [提交问题](https://github.com/Meguvizarchic/DexMeguviz/issues)

## 许可

项目采用 [Apache-2.0](LICENSE)。第三方组件及来源说明见 [NOTICE](NOTICE) 和 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)。
