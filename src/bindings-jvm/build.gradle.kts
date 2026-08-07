import java.util.Properties

plugins {
    kotlin("jvm") version "2.4.0" // keep in sync with configs.yml kotlin-version
    `maven-publish`
    signing
    id("org.jetbrains.dokka") version "2.2.0" // keep in sync with configs.yml dokka-version
    id("org.jetbrains.dokka-javadoc") version "2.2.0" // keep in sync with configs.yml dokka-version
}

// ── Coordinates + bundled runtime dependency versions.
//    Static publishing identity (groupId, artifactId) lives in gradle.properties.
//    The version and bundled dependency versions come from version.properties, which
//    build.sh generates from Cargo.toml (the single source of truth) so they cannot
//    drift. Every value is required: the build fails loudly if one is missing rather
//    than substituting a baked-in default. A -P override still wins over both files.
val generatedVersions = Properties().apply {
    val file = layout.projectDirectory.file("version.properties").asFile
    if (file.exists()) file.inputStream().use { load(it) }
}

fun requiredProperty(name: String): String =
    (providers.gradleProperty(name).orNull ?: generatedVersions.getProperty(name))
        .takeIf { !it.isNullOrBlank() }
        ?: error(
            "Required property '$name' is not defined. Static coordinates live in gradle.properties; " +
                "version/dependency versions are generated into version.properties by build.sh (run ./build.sh first) " +
                "or passed with -P$name=<value>.",
        )

val publishGroupId = requiredProperty("publishGroupId")
val publishArtifactId = requiredProperty("publishArtifactId")
val publishVersion = requiredProperty("publishVersion")
val jnaVersion = requiredProperty("jnaVersion")
val gsonVersion = requiredProperty("gsonVersion")
val kotlinVersion = requiredProperty("kotlinVersion")

group = publishGroupId
version = publishVersion

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:$jnaVersion")
    implementation("com.google.code.gson:gson:$gsonVersion")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")
}

kotlin {
    jvmToolchain(21) // keep in sync with configs.yml java-version
}

// ── Source layout ───────────────────────────────────────────────────────────────
// build.sh writes uniffi-generated + hand-maintained sources into generated/, and
// the host native library into generated/natives/<os>-<arch>/. Point the main source
// set at generated/ so `gradle jar` compiles exactly what build.sh produced.
val generatedDir = layout.projectDirectory.dir("generated")
val nativesDir = generatedDir.dir("natives")
val mergedJar = generatedDir.file("cloudformation-validate.jar")
val repoLicense = layout.projectDirectory.file("../../LICENSE")
val repoNotice = layout.projectDirectory.file("../../NOTICE")
val thirdPartyLicenses = layout.projectDirectory.file("THIRD-PARTY-LICENSES.txt")
val bindingReadme = layout.projectDirectory.file("README.md")

sourceSets {
    main {
        kotlin.setSrcDirs(listOf(generatedDir))
        // generated/ also holds the emitted jar and staged natives - only .kt is source.
        kotlin.exclude("**/*.jar", "natives/**")
    }
}

// The main jar written to generated/cloudformation-validate.jar, matching the name and
// contents build.sh previously produced by hand: classes + .kt sources (IDE nav) +
// host native under the JNA <os>-<arch>/ path + license/readme metadata.
tasks.named<Jar>("jar") {
    archiveFileName.set("cloudformation-validate.jar")
    destinationDirectory.set(generatedDir)
    includeEmptyDirs = false

    from(generatedDir) {
        include("**/*.kt") // bundle sources for IDE navigation, mirroring the old build
    }
    from(nativesDir) // contents land at the jar root as <os>-<arch>/lib*.{dylib,so,dll}
    from(repoLicense) { into("META-INF") }
    from(repoNotice) { into("META-INF") }
    from(bindingReadme) { into("META-INF") }
    from(thirdPartyLicenses) { into("META-INF") }

    manifest {
        attributes(
            "Implementation-Title" to "cloudformation-validate",
            "Implementation-Version" to publishVersion,
            "Implementation-Vendor" to "Amazon Web Services (AWS)",
            "Build-Jdk-Spec" to "21",
            "License" to "Apache-2.0",
            "Requires" to "net.java.dev.jna:jna:$jnaVersion, " +
                "com.google.code.gson:gson:$gsonVersion, " +
                "org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion",
        )
    }
}

// ── Javadoc via Dokka ───────────────────────────────────────────────────────────
// Dokka documents the Kotlin API. At a release checkout the generated sources are gone
// (only the merged jar remains), so re-extract the .kt from the merged jar into a
// scratch dir and point Dokka at it. When build.sh just ran, generated/ still holds the
// same sources; using the jar keeps a single, checkout-independent source of truth.
val dokkaSources = layout.buildDirectory.dir("dokka-sources")
val extractDokkaSources = tasks.register<Sync>("extractDokkaSources") {
    description = "Extracts the bundled Kotlin sources from the merged jar for Dokka."
    onlyIf {
        mergedJar.asFile.exists().also {
            if (!it) logger.warn("Merged jar ${mergedJar.asFile} absent; Dokka has no sources to document.")
        }
    }
    from({ zipTree(mergedJar) }) { include("**/*.kt") }
    into(dokkaSources)
}

dokka {
    dokkaSourceSets.main {
        sourceRoots.from(dokkaSources)
        classpath.from(configurations.named("compileClasspath"))
        jdkVersion.set(21)
        reportUndocumented.set(false)
        skipEmptyPackages.set(true)
    }
}

tasks.named("dokkaGenerate") {
    dependsOn(extractDokkaSources)
}

tasks.named("dokkaGeneratePublicationJavadoc") {
    dependsOn(extractDokkaSources)
}

val javadocJar = tasks.register<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaGeneratePublicationJavadoc").map { it.outputs })
    from(repoLicense) { into("META-INF") }
    from(repoNotice) { into("META-INF") }
}

// Sources jar: re-extract the .kt the merged jar bundles, so it works at a release
// checkout where the generated sources are absent from disk (only the jar is committed).
val sourcesJar = tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    includeEmptyDirs = false
    onlyIf { mergedJar.asFile.exists() }
    from({ zipTree(mergedJar) }) { include("**/*.kt") }
    from(repoLicense) { into("META-INF") }
    from(repoNotice) { into("META-INF") }
}

// ── Publication ─────────────────────────────────────────────────────────────────
publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = publishGroupId
            artifactId = publishArtifactId
            version = publishVersion

            artifact(mergedJar) { extension = "jar" }
            artifact(sourcesJar)
            artifact(javadocJar)

            pom {
                name.set("CloudFormation Validate")
                description.set("Fast, offline, embeddable validation for AWS CloudFormation templates")
                url.set("https://github.com/aws-cloudformation/cloudformation-validate")
                organization {
                    name.set("Amazon Web Services")
                    url.set("https://aws.amazon.com")
                }
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("aws-cloudformation")
                        name.set("AWS CloudFormation")
                        url.set("https://github.com/aws-cloudformation/cloudformation-validate")
                        organization.set("Amazon Web Services")
                        organizationUrl.set("https://aws.amazon.com/")
                    }
                }
                issueManagement {
                    system.set("GitHub")
                    url.set("https://github.com/aws-cloudformation/cloudformation-validate/issues")
                }
                ciManagement {
                    system.set("GitHub Actions")
                    url.set("https://github.com/aws-cloudformation/cloudformation-validate/actions")
                }
                scm {
                    connection.set("scm:git:https://github.com/aws-cloudformation/cloudformation-validate.git")
                    developerConnection.set("scm:git:ssh://git@github.com/aws-cloudformation/cloudformation-validate.git")
                    url.set("https://github.com/aws-cloudformation/cloudformation-validate")
                    tag.set(publishVersion)
                }
                withXml {
                    val dependencies = asNode().appendNode("dependencies")
                    fun publicationDependency(
                        group: String,
                        name: String,
                        dependencyVersion: String,
                        scope: String,
                    ) {
                        dependencies.appendNode("dependency").apply {
                            appendNode("groupId", group)
                            appendNode("artifactId", name)
                            appendNode("version", dependencyVersion)
                            appendNode("scope", scope)
                        }
                    }
                    publicationDependency("net.java.dev.jna", "jna", jnaVersion, "runtime")
                    publicationDependency("com.google.code.gson", "gson", gsonVersion, "runtime")
                    publicationDependency("org.jetbrains.kotlin", "kotlin-stdlib", kotlinVersion, "compile")
                }
            }
        }
    }

    // Local Maven-layout staging directory. Publishing here produces the signed
    // artifacts plus their .md5/.sha1 checksums under the standard groupId path,
    // which the centralBundle task zips into the Portal upload archive.
    repositories {
        maven {
            name = "staging"
            url = uri(layout.buildDirectory.dir("staging-deploy"))
        }
    }
}

// The published main artifact is the prebuilt merged jar, not this project's own jar
// task output - guard against publishing an accidentally host-only jar.
fun requireMergedJar() = require(mergedJar.asFile.exists()) {
    "Merged jar not found at ${mergedJar.asFile}. Run ./build.sh (and merge-jars.sh in CI) first."
}

tasks.withType<AbstractPublishToMaven>().configureEach {
    doFirst { requireMergedJar() }
}

// ── PGP signing - required by Maven Central, engaged only when a key is present ──
// signingKey / signingPassword resolve from -PsigningKey=... or the environment
// variables ORG_GRADLE_PROJECT_signingKey / ORG_GRADLE_PROJECT_signingPassword.
// signingKey must be the full ASCII-armored private key block.
val signingKey = findProperty("signingKey") as String?
val signingPassword = (findProperty("signingPassword") as String?) ?: ""
signing {
    setRequired { signingKey != null }
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["maven"])
    }
}

// ── Central Publisher Portal upload bundle ──────────────────────────────────────
// Zips the staged Maven layout into a single archive whose internal folder structure
// follows the Maven Repository Layout, as the Portal upload API requires.
// maven-metadata.* files are repository bookkeeping the Portal does not accept.
val centralBundle = tasks.register<Zip>("centralBundle") {
    group = "publishing"
    description = "Assembles the Central Publisher Portal upload bundle from the staged Maven layout."
    dependsOn("publishMavenPublicationToStagingRepository")
    from(layout.buildDirectory.dir("staging-deploy")) { exclude("**/maven-metadata.*") }
    destinationDirectory.set(layout.buildDirectory.dir("central"))
    archiveFileName.set("$publishArtifactId-$publishVersion-bundle.zip")
    doLast {
        logger.lifecycle("Central Portal bundle: ${archiveFile.get().asFile}")
    }
}
