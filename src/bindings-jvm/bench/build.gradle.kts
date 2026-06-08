plugins {
    kotlin("jvm") version "2.3.10"
    application
}

repositories {
    mavenCentral()
}

val bindingsJar = file("${rootProject.projectDir}/../generated/cloudformation-validate.jar")

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
