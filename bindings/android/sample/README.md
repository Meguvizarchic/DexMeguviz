# 可选Android宿主示例

从bindings/android运行 `gradlew.bat -Pdmg.sample=true :sample:assembleDebug`。默认设置不包含sample；库仍compileOnly Kotlin，示例作为宿主显式提供已批准的kotlin-stdlib 2.4.21。

应用使用原生Activity/View，无额外UI依赖或权限。点击运行查询后，在后台读5个项目自建DEX资产，打开有序SourceSet并执行两跳展开，展示状态、来源、行、路径和前沿；资产只作为bytes分析，从不ClassLoader装载。snapshot由try-with-resources释放，界面销毁后不再更新旧View。它不会扫描其他应用、连接网络或自动安装Hook。

隔离源码快照已使用项目原始Gradle任务构建Debug APK；尚未安装或运行设备/ART。示例构建成功不是设备验收证据，完整依赖闭包本次未单独捕获。资产的构造来源为tests/fixtures/generated/expand，非真实宿主APK。
