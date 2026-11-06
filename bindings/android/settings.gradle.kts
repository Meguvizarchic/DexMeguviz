pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

fun requireGradleJdk17(version: JavaVersion) {
    check(version == JavaVersion.VERSION_17) {
        "DexMeguviz Android builds require Gradle to run on JDK 17"
    }
}
requireGradleJdk17(JavaVersion.current())

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "DexMeguvizAndroid"
include(":dexmeguviz-android")

// Optional local host example; excluded from the library build by default.
if (providers.gradleProperty("dmg.sample").orNull == "true") {
    include(":sample")
}
