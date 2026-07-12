plugins {
    kotlin("jvm") version "2.4.0"
    jacoco
}

repositories {
    mavenCentral()
}

jacoco {
    toolVersion = "0.8.13"
}

val bindingsJar = file("${rootProject.projectDir}/../../generated/cloudformation-validate.jar")

dependencies {
    implementation(files(bindingsJar))
    implementation("net.java.dev.jna:jna:5.19.1")
    implementation("com.google.code.gson:gson:2.14.0")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.1")
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

    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    classDirectories.setFrom(
        zipTree(bindingsJar).matching {
            include("software/amazon/cloudformation/validate/**/*.class")
            exclude(
                "**/FfiConverter*",
                "**/ForeignBytes*",
                "**/RustBuffer*",
                "**/Uniffi*",
                "**/*Cleaner*",
                "**/NoPointer*",
                "**/UByteArray*",
            )
        },
    )

    reports {
        xml.required.set(true)
        html.required.set(true)
    }

    doLast {
        val reportFile = reports.xml.outputLocation.get().asFile
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        val report = factory.newDocumentBuilder().parse(reportFile).documentElement
        val counters = report.childNodes
        println("Kotlin coverage:")
        for (i in 0 until counters.length) {
            val node = counters.item(i)
            if (node.nodeName != "counter") continue
            val type = node.attributes.getNamedItem("type").nodeValue
            val covered = node.attributes.getNamedItem("covered").nodeValue.toInt()
            val missed = node.attributes.getNamedItem("missed").nodeValue.toInt()
            val total = covered + missed
            val pct = if (total > 0) 100.0 * covered / total else 0.0
            println("  %-12s %6d/%-6d %6.2f%%".format(type, covered, total, pct))
        }
    }
}

kotlin {
    jvmToolchain(21)
}
