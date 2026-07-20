plugins {
    kotlin("jvm") version "2.4.0"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("software.amazon.cloudformation:cloudformation-validate:latest.release")
}

application {
    mainClass.set("ValidateKt")
}

kotlin {
    jvmToolchain(21)
}
