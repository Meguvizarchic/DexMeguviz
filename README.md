<p align="center"><img src="docs/brand/DexMeguviz.svg" width="96" height="96" alt="DexMeguviz"></p>

# DexMeguviz

DexMeguviz 是面向 DEX 和 APK 的 C++20 静态查询库，提供 C 接口、桌面命令行和 Android Java/Kotlin 绑定。

## 能力

- 按顺序读取 DEX 和 APK 来源，查询类、方法、字段、类型、字符串及其引用。
- 按需读取指令、参数与注解，执行带深度和结果限制的关系查询。
- Android 接口支持同步查询与可取消的异步任务。桌面构建可按需启用 SQL 和持久缓存。

查询结果的完整性以声明的输入和查询范围为准。静态结果用于定位字节码中的候选，运行时绑定需由调用方在目标环境中确认。[支持矩阵](docs/support-matrix.md)

## 快速接入

### Android

通过 Maven Central 添加依赖。

```kotlin
dependencies {
    implementation("io.github.jichuo1.dexmeguviz:dexmeguviz-android:1.2.0")
}
```

该版本支持 Android 8.1 及以上（API 27），包含 `arm64-v8a` 和 `armeabi-v7a`，应用编译需使用 Android SDK 37.2 或更高版本。应用需提供 Kotlin 标准库，项目使用 2.4.21 构建。[Maven Central](https://repo.maven.apache.org/maven2/io/github/jichuo1/dexmeguviz/dexmeguviz-android/) · [Android 构建与查询示例](docs/getting-started.md#android)

### 桌面和原生项目

使用 CMake 3.25 或更高版本和 C++20 工具链构建。

```sh
cmake -S . -B build-local -DDMG_BUILD_TESTS=OFF -DDMG_BUILD_FUZZERS=OFF
cmake --build build-local --config Release --target dexmeguviz
```

用构建得到的 `dexmeguviz` 运行 `inspect app.apk --json` 可查看文件信息。桌面 SQL、持久缓存及其他可选工具的开关见[源码接入指南](docs/getting-started.md)。

## 文档

- [来源符号与文本](docs/contracts/source-symbol-text-v1.md)及[成员引用](docs/contracts/source-member-ref-v1.md)
- [方法事实](docs/contracts/jni-method-facts-v1.md)、[参数](docs/contracts/jni-method-parameters-v1.md)和[注解](docs/contracts/jni-annotations-v1.md)
- [提交问题](https://github.com/Meguvizarchic/DexMeguviz/issues)

## 许可

项目采用 [Apache-2.0](LICENSE)。第三方组件及来源见 [NOTICE](NOTICE) 和 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)。
