plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.jichuo1.dexmeguviz.sample"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }
    buildToolsVersion = "37.0.0"
    defaultConfig {
        applicationId = "io.github.jichuo1.dexmeguviz.sample"
        minSdk = 27
        targetSdk = 37
        versionCode = 1
        versionName = "0.0.0-local-sample"
        ndk { abiFilters += setOf("arm64-v8a", "armeabi-v7a") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":dexmeguviz-android"))
    // This application is the host; the library continues to use compileOnly.
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.4.21") { isTransitive = false }
}
