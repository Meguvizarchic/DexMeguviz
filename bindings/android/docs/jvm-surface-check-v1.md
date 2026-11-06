# JVM 已声明接口表对照（实验）

`bindings/android/tools/check_jvm_surface.py` 只读对照两个本地 JAR 或 AAR 的 Java 17 非预览 classfile。默认检查 `io/github/jichuo1/dexmeguviz/` 包，`--prefix` 可显式选择其他包。它记录输入 SHA-256，并检查旧包中 public 类及其声明的 public/protected 构造器、方法和字段是否缺失、可见性降低、静态属性变化、非 final 变为 final、非 abstract 变为 abstract，以及直接父类变更。

```text
python -B bindings/android/tools/check_jvm_surface.py --old <old.jar-or-aar> --new <new.jar-or-aar>
```

退出码 0 仅表示所检查的声明表未发现退化；1 表示发现问题或需要人工核对的直接父类变化；2 表示输入无效、被限制或 classfile 不支持。它对移动到父类的方法可能保守误报，也不核验接口表、嵌套类的所有可见性、Kotlin metadata、内联常量、泛型、反射、资源、native ABI、行为、Android/ART 或设备；不能将结果当成完整二进制兼容证明。压缩包重名、路径异常、嵌套类包歧义、多版本 classfile、不支持的 Java 版本及资源超限会拒绝。工具不写入输入或覆盖文件；不能抵御并发路径替换或证明来源真实性。

固定主机控制用旧/新 BIL runtime 验证三项公开构造器描述符缺失，修复候选不再缺失这三个签名，用同一 JAR/AAR 作零差异对照，并验证可见性/静态属性/final 变化和拒绝重复条目、嵌套类包歧义与多版本类；证据 `<LOCAL_PATH>
