import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

val enableAndroidPersistent = providers.gradleProperty("dmg.persistent").orNull?.let {
    require(it == "true" || it == "false") { "dmg.persistent must be true or false" }
    it == "true"
} ?: false

dependencies {
    // The host supplies Kotlin 2.4.21; never embed or publish it as a runtime dependency.
    compileOnly("org.jetbrains.kotlin:kotlin-stdlib:2.4.21") { isTransitive = false }
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

dependencyLocking {
    lockMode = LockMode.STRICT
}
configurations.matching { it.name == "releaseRuntimeClasspath" }.configureEach {
    resolutionStrategy.activateDependencyLocking()
}

tasks.register("verifyNoExternalRuntime") {
    val runtimeClasspath = configurations.named("releaseRuntimeClasspath")
    doLast {
        check(runtimeClasspath.get().files.isEmpty()) {
            "Android runtime dependencies must be explicitly reviewed before use"
        }
    }
}

tasks.register("verifyHostProvidedStdlib") {
    val compileClasspath = configurations.named("releaseCompileClasspath")
    doLast {
        val artifacts = compileClasspath.get().resolvedConfiguration.resolvedArtifacts
        val stdlib = artifacts.single { it.moduleVersion.id.group == "org.jetbrains.kotlin" && it.name == "kotlin-stdlib" }
        check(stdlib.moduleVersion.id.version == "2.4.21")
        val sha = MessageDigest.getInstance("SHA-256").digest(stdlib.file.readBytes())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        check(sha == "bd8250210584cb659847dce9cda660f8e9906e5def7fbebcea93dc6dcb6a88a3") { "unexpected cached Kotlin stdlib SHA-256" }
    }
}

tasks.matching { it.name == "compileReleaseKotlin" }.configureEach {
    dependsOn("verifyHostProvidedStdlib")
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn("verifyNoExternalRuntime")
}

android {
    namespace = "io.github.jichuo1.dexmeguviz"
    enableKotlin = true
    compileSdk {
        version = release(37) {
            minorApiLevel = 2
        }
    }
    buildToolsVersion = "37.0.0"
    ndkVersion = "30.0.16248370"

    defaultConfig {
        minSdk = 27
        ndk {
            abiFilters += setOf("arm64-v8a", "armeabi-v7a")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf("-DDMG_BUILD_TESTS=OFF", "-DDMG_WITH_SQLITE=OFF", "-DANDROID_STL=c++_static")
                if (enableAndroidPersistent) arguments += "-DDMG_ANDROID_PERSISTENT_FACTS=ON"
                targets += "dexmeguviz_android"
            }
        }
        consumerProguardFiles("consumer-rules.pro")
        if (enableAndroidPersistent) consumerProguardFiles("persistent-consumer.pro")
    }
    externalNativeBuild {
        cmake {
            path = file("CMakeLists.txt")
            version = "4.1.2"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    publishing { singleVariant("release") }
}

// AGP 9 variant API avoids the legacy AndroidLibrarySourceSet cast.
if (enableAndroidPersistent) {
    androidComponents {
        onVariants(selector().all()) { variant ->
            variant.sources.java?.addStaticSourceDirectory("src/persistent/java")
        }
    }
}

// Isolated local proof only; this repository is inside the build directory.
publishing {
    publications {
        register<MavenPublication>("localProbe") {
            groupId = "io.github.jichuo1.dexmeguviz"
            artifactId = "dexmeguviz-android"
            version = "0.0.0-local-prototype"
            afterEvaluate { from(components["release"]) }
        }
    }
    repositories { maven { name = "probe"; url = uri(layout.buildDirectory.dir("probe-repository")) } }
}
