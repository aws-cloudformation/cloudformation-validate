plugins {
    kotlin("jvm") version "2.3.10"
}

repositories {
    mavenCentral()
}

val bindingsJar = file("${rootProject.projectDir}/../../generated/cloudformation-validate.jar")

dependencies {
    implementation(files(bindingsJar))
    implementation("net.java.dev.jna:jna:5.18.1")
    implementation("com.google.code.gson:gson:2.14.0")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
}

tasks.test {
    useJUnitPlatform()

    testLogging {
        events("started", "passed", "skipped", "failed", "standardOut", "standardError")
        showStandardStreams = true
        showExceptions = true
        showCauses = true
        showStackTraces = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

kotlin {
    jvmToolchain(21)
}
