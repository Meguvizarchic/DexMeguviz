# ADR 0001 原生核心与公共接口

日期：2026-10-26。状态：工程启动默认决策；由 P0-03 核实工具链后确认或提交带证据的替代 ADR。此状态不表示构建已通过。

## 决策

使用 C++20 实现首个 portable native core；内部不向使用方公开 STL 或 C++ 类 ABI。对外使用 `dmg_` 前缀的 C ABI，JNI 和桌面 CLI 共用核心。Android 使用 Kotlin DSL 和 AAR，SQL 为桌面可选组件。

core 可先作为静态 target 链入各前端，Android 对外形成单一 `libdexmeguviz.so`。采用隐藏符号可见性和显式导出清单。Android C++ runtime、依赖静态/动态链接方式由 BIL 包装兼容性试验确认，不将 C++ 对象或分配所有权跨不受控 DSO 传递。

## 理由

该路线方便对照已有 AOSP/DexKit 原生代码、控制布局与批处理，并可在相同工具链下建立算法对照。C ABI 将长期接口与内部语言、容器和编译器分开。单语言首轮可减少构建和热路径边界复杂度。

Rust 是合理候选，但当前缺少足以推翻这一路线的实测或团队约束。语言本身不构成性能倍数证据。若调整，保留 Source/Query/Result 语义和公共接口，记录所有权、FFI、工具链、依赖与维护影响。

## 需完成的确认

- 实际 host compiler 与 Android NDK 对所用 C++20 子集的支持；首版不要求 C++ modules 或协程运行库。
- arm64-v8a、armeabi-v7a 的最小 native smoke build；桌面 host 至少一个真实平台。
- Android 4 KB/16 KB 包装和运行验证；其状态与仅编译通过分开。
- BIL 当前 C++17 targets 不受新 target 设置污染，JNI/依赖库打包无冲突。
- 对外符号、异常边界、allocator 所有权和许可证记录明确。

确认失败时先收窄所用语言特性或修复工具链配置；若需改语言或 ABI，提出具体替代决策和迁移范围，不默默混用两套内核。


## 本轮工具链确认

2026-10-26：MSVC19.51/CMake4.3.1-msvc1真实C++20及C consumer通过，MSVC AddressSanitizer通过；NDK30/Clang21/API27的arm64-v8a与armeabi-v7a只编译通过。继续采用C++20。Android AAR/JNI/运行时/4KB与16KB包装未验，BIL C++17工作区未改。详见docs/evidence/validation-summary.json。
