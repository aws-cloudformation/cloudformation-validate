plugins {
    kotlin("jvm") version "2.3.10"
    application
}

repositories {
    mavenCentral()
}

// Auto-detect the platform-specific bindings jar to match build.sh naming:
// cloudformation-validate-jvm-<os>-<arch>.jar
val bindingsOs = System.getProperty("os.name").lowercase().let {
    when {
        it.contains("mac") || it.contains("darwin") -> "darwin"
        it.contains("win") -> "win32"
        it.contains("nux") || it.contains("nix") -> "linux"
        else -> error("Unsupported OS for bindings jar: $it")
    }
}
val bindingsArch = System.getProperty("os.arch").lowercase().let {
    when (it) {
        "aarch64", "arm64" -> "aarch64"
        "x86_64", "amd64" -> "x86-64"
        else -> error("Unsupported architecture for bindings jar: $it")
    }
}
val bindingsJar = file("${rootProject.projectDir}/../generated/cloudformation-validate-jvm-$bindingsOs-$bindingsArch.jar")

dependencies {
    implementation(files(bindingsJar))
    implementation("net.java.dev.jna:jna:5.18.1")
    implementation("com.google.code.gson:gson:2.14.0")
}

application {
    mainClass.set("BenchmarkKt")
}

kotlin {
    jvmToolchain(21)
}
