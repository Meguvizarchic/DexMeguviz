# 可选 Android 宿主示例

在 `bindings/android` 目录下运行 `gradlew.bat -Pdmg.sample=true :sample:assembleDebug` 可构建示例 Debug APK。默认配置不包含 `:sample` 模块；核心 AAR 仍以 `compileOnly` 引用 Kotlin，本示例作为宿主应用显式引入了已批准的 `kotlin-stdlib:2.4.21`。

## 功能与设计边界

示例仅使用原生 `Activity` 与 `View` 构建界面，无额外 UI 库依赖或危险权限请求。点击按钮后，程序会在后台线程读取 5 个自建 DEX 资产，打开有序 `SourceSetSnapshot` 并执行两跳有界展开（`bounded_expand`），随后展示执行状态、来源数、结果行、路径与前沿数：

- 示例资产仅作为静态字节分析，从不由 `ClassLoader` 装载，也不会扫描其他应用、连接网络或安装 Hook。
- 快照由 `try-with-resources` 及时释放，界面销毁后不会回写已销毁的视图。

## 适用范围与验证说明

- 示例 Debug APK 使用项目原始 Gradle 任务在隔离环境构建完成；内置 DEX 资产源自 `tests/fixtures/generated/expand`，仅用于验证静态多来源展开接口，不代表真实宿主 APK 的负载或性能。
- 示例构建通过不替代真机安装、ART 运行或完整依赖图的验收测试。
