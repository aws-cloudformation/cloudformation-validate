import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import software.amazon.cloudformation.validate.JvmCelEngine
import software.amazon.cloudformation.validate.JvmRegoEngine
import software.amazon.cloudformation.validate.JvmSemanticModel
import software.amazon.cloudformation.validate.ValidateConfig
import software.amazon.cloudformation.validate.diagnostics.DetailedReport
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.gson.buildBindingsGson
import software.amazon.cloudformation.validate.rules.RuleFilterConfig
import software.amazon.cloudformation.validate.rules.Severity
import software.amazon.cloudformation.validate.templatemodel.PseudoParameterOverrides
import software.amazon.cloudformation.validate.version
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import java.util.jar.JarInputStream
import kotlin.math.sqrt
import kotlin.system.exitProcess

const val DEFAULT_STARTUP_TEMPLATE = "good/minimal.yaml"

fun main(args: Array<String>) {
    if (args.any { it == "-h" || it == "--help" }) {
        System.err.println(
            "Usage: gradle run --args=\"[TEMPLATE|DIR] [--engine rego|cel] [--iterations N]\"\n" +
                "       gradle run --args=\"--startup-probe [--engine rego|cel]\"",
        )
        return
    }

    val startupProbe = args.any { it == "--startup-probe" }

    val defaultTemplateDir = File(System.getProperty("user.dir")).resolve("../../resources/templates").canonicalPath
    val engineFlag =
        run {
            val idx = args.indexOf("--engine")
            if (idx < 0) return@run "rego"
            val value = args.getOrNull(idx + 1)
            if (value == null || value.startsWith("-")) {
                System.err.println("Error: --engine requires a value")
                exitProcess(2)
            }
            value
        }
    if (engineFlag != "rego" && engineFlag != "cel") {
        System.err.println("Error: --engine must be 'rego' or 'cel', got '$engineFlag'")
        exitProcess(2)
    }
    val iterations =
        run {
            val flagIdx = args.indexOf("--iterations")
            if (flagIdx < 0) return@run 20
            val raw = args.getOrNull(flagIdx + 1)
            if (raw == null) {
                System.err.println("Error: --iterations requires a value")
                exitProcess(2)
            }
            val parsed = raw.toIntOrNull()
            if (parsed == null || parsed <= 0) {
                System.err.println("Error: --iterations must be a positive integer, got '$raw'")
                exitProcess(2)
            }
            parsed
        }

    val positionalArg: String? =
        run {
            val flagsWithValues = setOf("--engine", "--iterations")
            var i = 0
            while (i < args.size) {
                if (flagsWithValues.contains(args[i])) {
                    i += 2
                    continue
                }
                if (!args[i].startsWith("-")) return@run args[i]
                i++
            }
            null
        }

    // Measure JNI native library load time. The first call to any UniFFI-generated function
    // triggers Native.register() for the Rust shared library. Use the lightweight version()
    // function to isolate library loading from schema/engine construction costs.
    val moduleLoadStart = System.nanoTime()
    val coreVersion = version()
    val moduleLoadMs = (System.nanoTime() - moduleLoadStart) / 1_000_000.0

    // Single ValidateConfig instance reused across all calls - avoids allocation per call.
    val benchValidateConfig = validateConfig()

    if (startupProbe) {
        exitProcess(runStartupProbe(engineFlag, coreVersion, moduleLoadMs, defaultTemplateDir, benchValidateConfig))
    }

    val templateDir = positionalArg ?: defaultTemplateDir

    val templates = collectFiles(File(templateDir))
    if (templates.isEmpty()) {
        System.err.println("No templates found in $templateDir")
        return
    }

    System.err.println("Benchmarking ${templates.size} templates, $iterations iterations, engine=$engineFlag, format=$formatFlag")

    val startupTemplate = templates[0]
    val startupBytes = startupTemplate.readBytes()
    val startupLabel =
        File(templateDir)
            .toPath()
            .relativize(startupTemplate.toPath())
            .toString()
            .replace('\\', '/')
            .ifEmpty { startupTemplate.name }
    val startup = measureStartup(engineFlag, moduleLoadMs, startupBytes, startupLabel, benchValidateConfig)
    val engine: Any = startup.engine

    val schemaInitSamples = emptyList<Double>()
    val engineInitSamples = listOf(startup.engineInitMs)
    val initSamples = engineInitSamples.toList()
    val coldInitMs = moduleLoadMs + initSamples[0]
    val subsequentInitSamples = emptyList<Double>()

    val reportDir = File(System.getProperty("user.dir")).resolve("../reports/$engineFlag").also { it.mkdirs() }
    val jsonDir =
        reportDir.resolve("json_$formatDir").also { dir ->
            // Clean previous output so stale reports from dropped/renamed templates are not left behind.
            if (dir.exists()) {
                check(dir.deleteRecursively()) { "Failed to remove previous json_$formatDir dir: $dir" }
            }
            dir.mkdirs()
        }

    val treeGson = buildBindingsGson()
    val outputGson = GsonBuilder().serializeNulls().setPrettyPrinting().create()

    val results = mutableListOf<TemplateResult>()
    val benchStart = System.nanoTime()

    for (tpl in templates) {
        val rel =
            File(templateDir)
                .toPath()
                .relativize(tpl.toPath())
                .toString()
                .replace('\\', '/')
                .ifEmpty { tpl.name }
        System.err.print("  $rel")

        val sizeBytes =
            try {
                tpl.length().toInt()
            } catch (e: Exception) {
                results.add(errorResult(rel, "read_error", e.message ?: "unknown"))
                continue
            }
        val bytes = tpl.readBytes()
        val jsonPath = reportPath(jsonDir, rel)
        val iterModelBuild = mutableListOf<Double>()
        val iterSchemaValidate = mutableListOf<Double>()
        val iterRuleEval = mutableListOf<Double>()
        val iterFinalize = mutableListOf<Double>()
        // Host-timed model parse - Kotlin-side nanoTime around JvmSemanticModel.parse.
        // Includes JNI dispatch + UniFFI marshalling of the parse call.
        val iterHostModel = mutableListOf<Double>()
        val iterEngineInternal = mutableListOf<Double>()
        // wall_clock = Kotlin-side nanoTime around validateDetailed() - includes JNI dispatch,
        // ByteArray→Rust Vec<u8> copy, UniFFI DetailedReport decoding.
        val iterWallClock = mutableListOf<Double>()
        var lastReport: DetailedReport? = null
        var failed = false

        repeat(iterations) { i ->
            if (failed) return@repeat
            // Standalone model parse - classify failures distinctly as parse_error.
            try {
                val tm0 = System.nanoTime()
                val parsed = JvmSemanticModel.parse(bytes)
                iterHostModel.add((System.nanoTime() - tm0) / 1_000_000.0)
                try {
                    parsed.destroy()
                } catch (_: Exception) {
                }
            } catch (e: Exception) {
                val parseFailureReport = validateDetailed(engine, bytes, benchValidateConfig, rel)
                writeReportJson(
                    jsonPath,
                    treeGson,
                    outputGson,
                    parseFailureReport,
                    engineFlag,
                    zeroBenchmarkMetrics(),
                    normalizeParseFailure = true,
                )
                results.add(errorResult(rel, "parse_error", e.message ?: "unknown"))
                failed = true
                return@repeat
            }

            try {
                val t0 = System.nanoTime()
                val report = validateDetailed(engine, bytes, benchValidateConfig, rel)
                val wallMs = (System.nanoTime() - t0) / 1_000_000.0
                iterModelBuild.add(report.performance.modelBuild.durationMs)
                iterSchemaValidate.add(report.performance.schemaValidate.durationMs)
                iterRuleEval.add(report.performance.ruleEvaluation.durationMs)
                iterFinalize.add(report.performance.diagnosticFinalize.durationMs)
                iterEngineInternal.add(report.performance.validateTotal.durationMs)
                iterWallClock.add(wallMs)
                if (i == iterations - 1) lastReport = report
            } catch (e: Exception) {
                results.add(errorResult(rel, "error", e.message ?: "unknown"))
                failed = true
            }
        }
        if (failed) continue

        val report = lastReport!!
        val firstEngineInternalMs = iterEngineInternal[0]
        val subsequentEngineInternalMs = if (iterations > 1) medianOf(iterEngineInternal.drop(1)) else null
        val medianEngineInternal = medianOf(iterEngineInternal)
        val firstWallClockMs = iterWallClock[0]
        val subsequentWallClockMs = if (iterations > 1) medianOf(iterWallClock.drop(1)) else null
        val medianWallClock = medianOf(iterWallClock)
        val firstHostModelMs = iterHostModel[0]
        val subsequentHostModelMs = if (iterations > 1) medianOf(iterHostModel.drop(1)) else null
        val medianHostModel = medianOf(iterHostModel)
        // Binding overhead: median of per-iteration (wall_clock − engine_internal) differences.
        // This captures JNI dispatch + UniFFI marshalling cost for each individual call.
        val perIterOverhead = iterWallClock.zip(iterEngineInternal) { w, e -> w - e }
        val bindingOverheadMs = round4(medianOf(perIterOverhead))

        val metrics =
            perTemplateMetricsJson(
                iterations,
                iterHostModel,
                iterModelBuild,
                iterSchemaValidate,
                iterRuleEval,
                iterFinalize,
                iterEngineInternal,
                iterWallClock,
                bindingOverheadMs,
            )
        writeReportJson(jsonPath, treeGson, outputGson, report, engineFlag, metrics, normalizeParseFailure = false)

        val tr =
            TemplateResult(
                file = rel,
                status = "ok",
                sizeBytes = sizeBytes,
                resources = report.metadata.resourcesScanned.toInt(),
                fatal =
                    report.metadata.counts.fatal
                        .toInt(),
                errors =
                    report.metadata.counts.errors
                        .toInt(),
                warnings =
                    report.metadata.counts.warnings
                        .toInt(),
                informational =
                    report.metadata.counts.informational
                        .toInt(),
                diagCount = report.diagnostics.size,
                hostModelMs = medianHostModel,
                firstMeasuredHostModelMs = firstHostModelMs,
                subsequentHostModelMs = subsequentHostModelMs,
                modelBuildMs = medianOf(iterModelBuild),
                schemaValidateMs = medianOf(iterSchemaValidate),
                ruleEvalMs = medianOf(iterRuleEval),
                diagnosticFinalizeMs = medianOf(iterFinalize),
                engineInternalMs = medianEngineInternal,
                firstMeasuredEngineInternalMs = firstEngineInternalMs,
                subsequentEngineInternalMs = subsequentEngineInternalMs,
                wallClockMs = medianWallClock,
                firstMeasuredWallClockMs = firstWallClockMs,
                subsequentWallClockMs = subsequentWallClockMs,
                wallClockTotalMs = iterWallClock.sum(),
                bindingOverheadMs = bindingOverheadMs,
            )
        System.err.println(
            "  model=${tr.hostModelMs.format(4)}ms  engine=${tr.engineInternalMs.format(4)}ms  wall=${tr.wallClockMs.format(4)}ms  ${tr.errors}E ${tr.warnings}W ${tr.informational}I",
        )
        results.add(tr)
    }

    val totalWallMs = (System.nanoTime() - benchStart) / 1_000_000.0

    val ok = results.filter { it.status == "ok" }
    val failures = results.filter { it.status != "ok" }

    val modelBuildVec = ok.map { it.modelBuildMs }
    val schemaValidateVec = ok.map { it.schemaValidateMs }
    val ruleEvalVec = ok.map { it.ruleEvalMs }
    val finalizeVec = ok.map { it.diagnosticFinalizeMs }
    val engineInternalVec = ok.map { it.engineInternalMs }
    val firstEngineInternalVec = ok.map { it.firstMeasuredEngineInternalMs }
    val subsequentEngineInternalVec = ok.mapNotNull { it.subsequentEngineInternalMs }
    val wallClockVec = ok.map { it.wallClockMs }
    val firstWallClockVec = ok.map { it.firstMeasuredWallClockMs }
    val subsequentWallClockVec = ok.mapNotNull { it.subsequentWallClockMs }
    val hostModelVec = ok.map { it.hostModelMs }
    val firstHostModelVec = ok.map { it.firstMeasuredHostModelMs }
    val subsequentHostModelVec = ok.mapNotNull { it.subsequentHostModelMs }
    val overheadVec = ok.map { it.bindingOverheadMs }

    val throughputPerSec =
        run {
            // Throughput denominator: sum of host-timed validate calls for successful templates only.
            // This excludes file I/O, standalone model benchmarks, logging overhead, and failures.
            val measuredValidationWallMs = ok.sumOf { it.wallClockTotalMs }
            if (measuredValidationWallMs > 0) ok.size * iterations / (measuredValidationWallMs / 1000.0) else 0.0
        }
    val measuredValidationWallMs = ok.sumOf { it.wallClockTotalMs }

    val (corpusFingerprint, corpusFileCount) = computeCorpusFingerprint(File(templateDir))
    val runFingerprint = sha256Hex("$corpusFingerprint|$engineFlag|$formatFlag|$iterations")

    // Provenance is assembled after all timed work so its cargo/rustc subprocess spawns never
    // contaminate the measurements.
    val provenanceObj = provenanceJson(coreVersion)

    val perfObj =
        JsonObject().apply {
            addProperty("module_load_ms", round4(startup.moduleLoadMs))
            add("startup", startupSectionJson(startup))
            add("init_ms", statsToJsonObject(initSamples))
            addProperty("cold_init_ms", round4(coldInitMs))
            add("warm_init_ms", statsToJsonObject(subsequentInitSamples))
            add("subsequent_init_ms", statsToJsonObject(subsequentInitSamples))
            add("schema_init_ms", statsToJsonObject(schemaInitSamples))
            add("engine_init_ms", statsToJsonObject(engineInitSamples))
            addProperty("total_wall_ms", round4(totalWallMs))
            addProperty("measured_validation_wall_ms", round4(measuredValidationWallMs))
            addProperty("throughput_per_sec", round4(throughputPerSec))
            add("model_build_ms", statsToJsonObject(modelBuildVec))
            add("schema_validate_ms", statsToJsonObject(schemaValidateVec))
            add("rule_evaluation_ms", statsToJsonObject(ruleEvalVec))
            add("diagnostic_finalize_ms", statsToJsonObject(finalizeVec))
            add("engine_internal_ms", statsToJsonObject(engineInternalVec))
            add("first_measured_engine_internal_ms", statsToJsonObject(firstEngineInternalVec))
            add("subsequent_engine_internal_ms", statsToJsonObject(subsequentEngineInternalVec))
            // cold_*/warm_* are legacy aliases for first_measured_*/subsequent_* respectively.
            add("cold_engine_internal_ms", statsToJsonObject(firstEngineInternalVec))
            add("warm_engine_internal_ms", statsToJsonObject(subsequentEngineInternalVec))
            add("wall_clock_ms", statsToJsonObject(wallClockVec))
            add("first_measured_wall_clock_ms", statsToJsonObject(firstWallClockVec))
            add("subsequent_wall_clock_ms", statsToJsonObject(subsequentWallClockVec))
            add("cold_wall_clock_ms", statsToJsonObject(firstWallClockVec))
            add("warm_wall_clock_ms", statsToJsonObject(subsequentWallClockVec))
            add("host_model_ms", statsToJsonObject(hostModelVec))
            add("first_measured_host_model_ms", statsToJsonObject(firstHostModelVec))
            add("subsequent_host_model_ms", statsToJsonObject(subsequentHostModelVec))
            add("cold_host_model_ms", statsToJsonObject(firstHostModelVec))
            add("warm_host_model_ms", statsToJsonObject(subsequentHostModelVec))
            add("binding_overhead_ms", statsToJsonObject(overheadVec))
        }

    val diagObj =
        JsonObject().apply {
            addProperty("total_fatal", ok.sumOf { it.fatal })
            addProperty("total_errors", ok.sumOf { it.errors })
            addProperty("total_warnings", ok.sumOf { it.warnings })
            addProperty("total_informational", ok.sumOf { it.informational })
        }

    val failuresArr =
        JsonArray().apply {
            for (r in failures) {
                add(
                    JsonObject().apply {
                        addProperty("file", r.file)
                        addProperty("status", r.status)
                        addProperty("error", r.errorMsg ?: "unknown")
                    },
                )
            }
        }

    val aggregateObj =
        JsonObject().apply {
            addProperty("timestamp", isoNow())
            addProperty("engine", engineFlag)
            addProperty("binding", "jvm")
            addProperty("detail_level", formatFlag)
            addProperty("template_dir", templateDir)
            add("provenance", provenanceObj)
            addProperty("templates_total", results.size)
            addProperty("templates_ok", ok.size)
            addProperty("templates_failed", failures.size)
            addProperty("iterations_per_template", iterations)
            addProperty("corpus_fingerprint", corpusFingerprint)
            addProperty("corpus_file_count", corpusFileCount)
            addProperty("run_fingerprint", runFingerprint)
            add("performance", perfObj)
            add("diagnostics", diagObj)
            add("failures", failuresArr)
        }
    reportDir.resolve("aggregate_$formatDir.json").writeText(outputGson.toJson(aggregateObj))

    val md =
        generateMarkdown(
            MarkdownInput(
                allResults = results,
                okResults = ok,
                failedResults = failures,
                startup = startup,
                provenance = provenanceObj,
                modelBuild = modelBuildVec,
                schemaValidate = schemaValidateVec,
                ruleEval = ruleEvalVec,
                diagnosticFinalize = finalizeVec,
                engineInternal = engineInternalVec,
                firstEngineInternal = firstEngineInternalVec,
                subsequentEngineInternal = subsequentEngineInternalVec,
                wallClock = wallClockVec,
                firstWallClock = firstWallClockVec,
                subsequentWallClock = subsequentWallClockVec,
                hostModel = hostModelVec,
                firstHostModel = firstHostModelVec,
                subsequentHostModel = subsequentHostModelVec,
                overhead = overheadVec,
                initSamples = initSamples,
                subsequentInitSamples = subsequentInitSamples,
                schemaInitSamples = schemaInitSamples,
                engineInitSamples = engineInitSamples,
                totalWallMs = totalWallMs,
                throughputPerSec = throughputPerSec,
                engineName = engineFlag,
                iterations = iterations,
                corpusFingerprint = corpusFingerprint,
                corpusFileCount = corpusFileCount,
            ),
        )
    reportDir.resolve("report_$formatDir.md").writeText(md)

    System.err.println("\nBenchmark complete: ${ok.size} ok, ${failures.size} failed ($iterations iterations/template)")
    System.err.println(
        "startup: module_load=${startup.moduleLoadMs.format(4)}ms  consumer_init(${startup.consumerInitScope})=${startup.consumerInitMs.format(4)}ms  first_validate=${startup.first.hostMs.format(4)}ms",
    )
    System.err.println(
        "schema_init (median): ${medianOf(schemaInitSamples).format(4)}ms  engine_init (median): ${
            medianOf(
                engineInitSamples,
            ).format(4)
        }ms",
    )
    System.err.println(
        "engine_internal (median): median=${medianOf(engineInternalVec).format(4)}ms p99=${
            percentileOf(
                engineInternalVec,
                99.0,
            ).format(4)
        }ms max=${maxOf(engineInternalVec).format(4)}ms",
    )
    System.err.println(
        "wall_clock     (median): median=${medianOf(wallClockVec).format(4)}ms p99=${
            percentileOf(
                wallClockVec,
                99.0,
            ).format(4)
        }ms max=${maxOf(wallClockVec).format(4)}ms",
    )
    System.err.println("Throughput: ${throughputPerSec.format(2)} validations/sec")
    System.err.println("Corpus fingerprint: $corpusFingerprint ($corpusFileCount files)")
    System.err.println("Reports written to $reportDir")

    if (engine is AutoCloseable) engine.close()
}

private data class FirstValidation(
    val hostMs: Double,
    val internalMs: Double,
    val modelBuildMs: Double,
    val schemaValidateMs: Double,
    val ruleEvaluationMs: Double,
    val diagnosticFinalizeMs: Double,
)

private data class StartupMeasurement(
    val startupTemplate: String,
    val moduleLoadMs: Double,
    val consumerInitScope: String,
    val consumerInitMs: Double,
    val schemaInitMs: Double?,
    val engineInitMs: Double,
    val first: FirstValidation,
    val internalTimeToFirstResultMs: Double,
    val engine: Any,
)

private fun measureStartup(
    engineFlag: String,
    moduleLoadMs: Double,
    startupBytes: ByteArray,
    startupLabel: String,
    benchmarkConfig: ValidateConfig,
): StartupMeasurement {
    val engineStart = System.nanoTime()
    val engine = newEngine(engineFlag)
    val engineInitMs = (System.nanoTime() - engineStart) / 1_000_000.0
    // The JVM engine constructor embeds a SchemaValidator, so consumer init is engine-only.
    val consumerInitMs = engineInitMs

    val validateStart = System.nanoTime()
    val report = validateDetailed(engine, startupBytes, benchmarkConfig, startupLabel)
    val hostMs = (System.nanoTime() - validateStart) / 1_000_000.0

    val perf = report.performance
    val first =
        FirstValidation(
            hostMs = hostMs,
            internalMs = perf.validateTotal.durationMs,
            modelBuildMs = perf.modelBuild.durationMs,
            schemaValidateMs = perf.schemaValidate.durationMs,
            ruleEvaluationMs = perf.ruleEvaluation.durationMs,
            diagnosticFinalizeMs = perf.diagnosticFinalize.durationMs,
        )

    return StartupMeasurement(
        startupTemplate = startupLabel,
        moduleLoadMs = moduleLoadMs,
        consumerInitScope = "engine",
        consumerInitMs = consumerInitMs,
        schemaInitMs = null,
        engineInitMs = engineInitMs,
        first = first,
        internalTimeToFirstResultMs = moduleLoadMs + consumerInitMs + hostMs,
        engine = engine,
    )
}

private fun firstValidationJson(first: FirstValidation): JsonObject =
    JsonObject().apply {
        addProperty("host_ms", round4(first.hostMs))
        addProperty("internal_ms", round4(first.internalMs))
        addProperty("model_build_ms", round4(first.modelBuildMs))
        addProperty("schema_validate_ms", round4(first.schemaValidateMs))
        addProperty("rule_evaluation_ms", round4(first.ruleEvaluationMs))
        addProperty("diagnostic_finalize_ms", round4(first.diagnosticFinalizeMs))
    }

private fun startupSectionJson(startup: StartupMeasurement): JsonObject =
    JsonObject().apply {
        addProperty("startup_template", startup.startupTemplate)
        addProperty("module_load_ms", round4(startup.moduleLoadMs))
        add(
            "consumer_init",
            JsonObject().apply {
                addProperty("scope", startup.consumerInitScope)
                addProperty("duration_ms", round4(startup.consumerInitMs))
            },
        )
        if (startup.schemaInitMs != null) {
            addProperty("schema_init_ms", round4(startup.schemaInitMs))
        } else {
            add("schema_init_ms", JsonNull.INSTANCE)
        }
        addProperty("engine_init_ms", round4(startup.engineInitMs))
        add("first_validation", firstValidationJson(startup.first))
        addProperty("internal_time_to_first_result_ms", round4(startup.internalTimeToFirstResultMs))
    }

private fun runStartupProbe(
    engineFlag: String,
    coreVersion: String,
    moduleLoadMs: Double,
    defaultTemplateDir: String,
    benchmarkConfig: ValidateConfig,
): Int {
    val startupFile = File(defaultTemplateDir).resolve(DEFAULT_STARTUP_TEMPLATE)
    val startupBytes =
        try {
            startupFile.readBytes()
        } catch (e: Exception) {
            System.err.println("Error: failed to read startup template '${startupFile.path}': ${e.message}")
            return 1
        }
    val startupLabel = startupFile.name

    val startup = measureStartup(engineFlag, moduleLoadMs, startupBytes, startupLabel, benchmarkConfig)
    val engineName = engineName(startup.engine)

    val probe = startupSectionJson(startup)
    probe.addProperty("binding", "jvm")
    probe.addProperty("engine", engineName)
    probe.add("versions", provenanceJson(coreVersion))

    println(GsonBuilder().serializeNulls().create().toJson(probe))

    if (startup.engine is AutoCloseable) startup.engine.close()
    return 0
}

private data class ArtifactVersion(
    val version: String,
    val source: String,
)

private fun provenanceJson(coreVersion: String): JsonObject {
    val artifact = resolveArtifactVersion(coreVersion)
    return JsonObject().apply {
        addProperty("cloudformation_validate", coreVersion)
        add(
            "binding_artifact",
            JsonObject().apply {
                addProperty("kind", "jar")
                addProperty("version", artifact.version)
                addProperty("source", artifact.source)
            },
        )
        addProperty("cargo", envOrQuery("BENCHMARK_CARGO_VERSION", "cargo"))
        addProperty("rustc", envOrQuery("BENCHMARK_RUSTC_VERSION", "rustc"))
        addProperty("runtime", jvmRuntimeLabel())
    }
}

private fun resolveArtifactVersion(fallback: String): ArtifactVersion {
    val pkgVersion = JvmRegoEngine::class.java.`package`?.implementationVersion
    if (!pkgVersion.isNullOrBlank()) {
        return ArtifactVersion(pkgVersion, "package-implementation-version")
    }
    val manifestVersion = readJarManifestImplementationVersion()
    if (!manifestVersion.isNullOrBlank()) {
        return ArtifactVersion(manifestVersion, "jar-manifest")
    }
    return ArtifactVersion(fallback, "fallback:core-version")
}

private fun readJarManifestImplementationVersion(): String? =
    try {
        val location =
            JvmRegoEngine::class.java.protectionDomain
                ?.codeSource
                ?.location
        if (location == null) {
            null
        } else {
            location.openStream().use { stream ->
                JarInputStream(stream).use { jar ->
                    jar.manifest?.mainAttributes?.getValue("Implementation-Version")
                }
            }
        }
    } catch (_: Exception) {
        null
    }

private fun jvmRuntimeLabel(): String {
    val runtimeVersion = System.getProperty("java.version") ?: "unknown"
    val vendor = System.getProperty("java.vendor") ?: "unknown"
    return "jvm $runtimeVersion ($vendor)"
}

private fun envOrQuery(
    varName: String,
    tool: String,
): String {
    val value = System.getenv(varName)
    if (value != null && value.trim().isNotEmpty()) return value.trim()
    return queryToolVersion(tool)
}

private fun queryToolVersion(tool: String): String =
    try {
        val process = ProcessBuilder(tool, "--version").start()
        val finished = process.waitFor(10, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            "unknown"
        } else if (process.exitValue() == 0) {
            val output = process.inputStream.bufferedReader().use { it.readText() }
            output
                .lineSequence()
                .firstOrNull()
                ?.trim()
                .takeUnless { it.isNullOrEmpty() } ?: "unknown"
        } else {
            "unknown"
        }
    } catch (_: Exception) {
        "unknown"
    }

private fun newEngine(engineFlag: String): Any =
    when (engineFlag) {
        "cel" -> JvmCelEngine(engineConfig())
        else -> JvmRegoEngine(engineConfig())
    }

private fun engineName(engine: Any): String =
    when (engine) {
        is JvmCelEngine -> engine.engineName()
        is JvmRegoEngine -> engine.engineName()
        else -> throw IllegalArgumentException("Unknown engine type")
    }

private fun computeCorpusFingerprint(root: File): Pair<String, Int> {
    // MUST mirror Rust and TS: SHA-256 over sorted "relpath\tsha256(content)\n" lines.
    val files = collectFiles(root)
    val outer = MessageDigest.getInstance("SHA-256")
    for (f in files) {
        val content = f.readBytes()
        val fileHash = sha256Hex(content)
        val rel =
            root
                .toPath()
                .relativize(f.toPath())
                .toString()
                .replace('\\', '/')
                .ifEmpty { f.name }
        outer.update("$rel\t$fileHash\n".toByteArray(Charsets.UTF_8))
    }
    return outer.digest().joinToString("") { "%02x".format(it) } to files.size
}

private fun sha256Hex(data: String): String = sha256Hex(data.toByteArray(Charsets.UTF_8))

private fun sha256Hex(data: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

private fun validateDetailed(
    engine: Any,
    template: ByteArray,
    config: ValidateConfig,
    filePath: String,
): DetailedReport =
    when (engine) {
        is JvmCelEngine -> engine.validateDetailed(template, config, filePath)
        is JvmRegoEngine -> engine.validateDetailed(template, config, filePath)
        else -> throw IllegalArgumentException("Unknown engine type")
    }

fun engineConfig() = EngineConfig(customRules = listOf(), guardRules = listOf())

fun validateConfig() =
    ValidateConfig(
        include = RuleFilterConfig(),
        exclude = RuleFilterConfig(),
        severityLevel = Severity.DEBUG,
        parameterOverrides = mapOf(),
        pseudoParameterOverrides = PseudoParameterOverrides(),
        strict = false,
    )

private val TEMPLATE_EXTENSIONS = setOf("yaml", "yml", "json")

private fun collectFiles(fileOrDir: File): List<File> {
    if (fileOrDir.isFile) return listOf(fileOrDir)
    return fileOrDir
        .walkTopDown()
        .filter { it.isFile && it.extension in TEMPLATE_EXTENSIONS }
        .toList()
        .sortedBy { it.path }
}

private fun reportPath(
    jsonDir: File,
    relativePath: String,
): File {
    var stem = relativePath.replace("/", "_")
    for ((extension, replacement) in listOf(".yaml" to "_yaml", ".yml" to "_yml", ".json" to "_json")) {
        if (stem.endsWith(extension)) {
            stem = stem.removeSuffix(extension) + replacement
            break
        }
    }
    return jsonDir.resolve("$stem.json")
}

private fun iterationMetricsJson(
    hostModel: Double,
    modelBuild: Double,
    schemaValidate: Double,
    ruleEval: Double,
    finalize: Double,
    engineInternal: Double,
    wallClock: Double,
): JsonObject =
    JsonObject().apply {
        addProperty("hostModelMs", round4(hostModel))
        addProperty("modelBuildMs", round4(modelBuild))
        addProperty("schemaValidateMs", round4(schemaValidate))
        addProperty("ruleEvaluationMs", round4(ruleEval))
        addProperty("diagnosticFinalizeMs", round4(finalize))
        addProperty("engineInternalMs", round4(engineInternal))
        addProperty("wallClockMs", round4(wallClock))
    }

private fun subsequentMetric(vals: List<Double>): JsonElement = if (vals.size > 1) JsonPrimitive(round4(medianOf(vals.drop(1)))) else JsonNull.INSTANCE

private fun perTemplateMetricsJson(
    iterations: Int,
    hostModel: List<Double>,
    modelBuild: List<Double>,
    schemaValidate: List<Double>,
    ruleEval: List<Double>,
    finalize: List<Double>,
    engineInternal: List<Double>,
    wallClock: List<Double>,
    bindingOverheadMs: Double,
): JsonObject {
    fun firstMeasured() =
        iterationMetricsJson(
            hostModel[0],
            modelBuild[0],
            schemaValidate[0],
            ruleEval[0],
            finalize[0],
            engineInternal[0],
            wallClock[0],
        )

    val subsequent =
        JsonObject().apply {
            addProperty("sampleCount", (wallClock.size - 1).coerceAtLeast(0))
            add("hostModelMs", subsequentMetric(hostModel))
            add("modelBuildMs", subsequentMetric(modelBuild))
            add("schemaValidateMs", subsequentMetric(schemaValidate))
            add("ruleEvaluationMs", subsequentMetric(ruleEval))
            add("diagnosticFinalizeMs", subsequentMetric(finalize))
            add("engineInternalMs", subsequentMetric(engineInternal))
            add("wallClockMs", subsequentMetric(wallClock))
        }

    fun steadyOrFirst(vals: List<Double>): Double = if (vals.size > 1) medianOf(vals.drop(1)) else vals[0]
    val steadyState =
        iterationMetricsJson(
            steadyOrFirst(hostModel),
            steadyOrFirst(modelBuild),
            steadyOrFirst(schemaValidate),
            steadyOrFirst(ruleEval),
            steadyOrFirst(finalize),
            steadyOrFirst(engineInternal),
            steadyOrFirst(wallClock),
        )

    return JsonObject().apply {
        addProperty("iterations", iterations)
        add("firstMeasured", firstMeasured())
        add("subsequent", subsequent)
        add("firstIteration", firstMeasured())
        add("steadyState", steadyState)
        addProperty("bindingOverheadMs", bindingOverheadMs)
    }
}

private fun zeroBenchmarkMetrics(): JsonObject {
    fun zeroIteration() =
        JsonObject().apply {
            addProperty("hostModelMs", 0.0)
            addProperty("modelBuildMs", 0.0)
            addProperty("schemaValidateMs", 0.0)
            addProperty("ruleEvaluationMs", 0.0)
            addProperty("diagnosticFinalizeMs", 0.0)
            addProperty("engineInternalMs", 0.0)
            addProperty("wallClockMs", 0.0)
        }
    return JsonObject().apply {
        addProperty("iterations", 0)
        add("firstMeasured", zeroIteration())
        add(
            "subsequent",
            JsonObject().apply {
                addProperty("sampleCount", 0)
                add("hostModelMs", JsonNull.INSTANCE)
                add("modelBuildMs", JsonNull.INSTANCE)
                add("schemaValidateMs", JsonNull.INSTANCE)
                add("ruleEvaluationMs", JsonNull.INSTANCE)
                add("diagnosticFinalizeMs", JsonNull.INSTANCE)
                add("engineInternalMs", JsonNull.INSTANCE)
                add("wallClockMs", JsonNull.INSTANCE)
            },
        )
        add("firstIteration", zeroIteration())
        add("steadyState", zeroIteration())
        addProperty("bindingOverheadMs", 0.0)
    }
}

private fun normalizeParseFailureReport(report: JsonObject) {
    report.add("diagnostics", JsonArray())
    val counts = report.getAsJsonObject("metadata").getAsJsonObject("counts")
    for (name in listOf("fatal", "errors", "warnings", "informational", "debug")) {
        counts.addProperty(name, 0)
    }
    val performance = report.getAsJsonObject("performance")
    for (name in listOf(
        "schemaInit",
        "engineInit",
        "modelBuild",
        "schemaValidate",
        "ruleEvaluation",
        "diagnosticFinalize",
        "validateTotal",
    )) {
        performance.getAsJsonObject(name).addProperty("durationMs", 0.0)
    }
}

private fun writeReportJson(
    dest: File,
    treeGson: Gson,
    outputGson: Gson,
    report: DetailedReport,
    engineFlag: String,
    metrics: JsonObject,
    normalizeParseFailure: Boolean,
) {
    val reportElement = treeGson.toJsonTree(report).asJsonObject
    if (normalizeParseFailure) normalizeParseFailureReport(reportElement)
    reportElement.addProperty("engine", engineFlag)
    reportElement.addProperty("binding", "jvm")
    reportElement.addProperty("detailLevel", formatFlag)
    reportElement.add("benchmarkMetrics", metrics)
    dest.writeText(outputGson.toJson(reportElement))
}

private fun minOf(vals: List<Double>): Double = vals.minOrNull() ?: 0.0

private fun maxOf(vals: List<Double>): Double = vals.maxOrNull() ?: 0.0

private fun avgOf(vals: List<Double>): Double = if (vals.isEmpty()) 0.0 else vals.sum() / vals.size

private fun stddevOf(vals: List<Double>): Double {
    if (vals.size < 2) return 0.0
    val mean = avgOf(vals)
    val variance = vals.sumOf { (it - mean) * (it - mean) } / (vals.size - 1)
    return sqrt(variance)
}

private fun medianOf(vals: List<Double>): Double {
    if (vals.isEmpty()) return 0.0
    val s = vals.sorted()
    val mid = s.size / 2
    return if (s.size % 2 == 0) (s[mid - 1] + s[mid]) / 2.0 else s[mid]
}

private fun percentileOf(
    vals: List<Double>,
    pct: Double,
): Double {
    if (vals.isEmpty()) return 0.0
    val s = vals.sorted()
    val rank = (pct / 100.0) * (s.size - 1)
    val lo = rank.toInt()
    val hi = (lo + 1).coerceAtMost(s.size - 1)
    val frac = rank - lo
    return s[lo] + frac * (s[hi] - s[lo])
}

private fun statsToJsonObject(vals: List<Double>): JsonObject {
    val obj = JsonObject()
    obj.addProperty("count", vals.size)
    obj.addProperty("min", round4(minOf(vals)))
    obj.addProperty("avg", round4(avgOf(vals)))
    obj.addProperty("stddev", round4(stddevOf(vals)))
    obj.addProperty("median", round4(medianOf(vals)))
    obj.addProperty("p90", round4(percentileOf(vals, 90.0)))
    obj.addProperty("p95", round4(percentileOf(vals, 95.0)))
    obj.addProperty("p99", round4(percentileOf(vals, 99.0)))
    obj.addProperty("max", round4(maxOf(vals)))
    obj.addProperty("total", round4(vals.sum()))
    return obj
}

private fun round4(v: Double): Double = Math.round(v * 10000.0) / 10000.0

private fun Double.format(decimals: Int): String = "%.${decimals}f".format(this)

private fun isoNow(): String = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC).format(Instant.now())

private fun fmtBytes(n: Int): String =
    when {
        n >= 1_048_576 -> "${"%.1f".format(n / 1_048_576.0)} MB"
        n >= 1024 -> "${"%.1f".format(n / 1024.0)} KB"
        else -> "$n B"
    }

private data class TemplateResult(
    val file: String,
    val status: String,
    val sizeBytes: Int,
    val resources: Int,
    val fatal: Int,
    val errors: Int,
    val warnings: Int,
    val informational: Int,
    val diagCount: Int,
    val hostModelMs: Double,
    val firstMeasuredHostModelMs: Double,
    val subsequentHostModelMs: Double?,
    val modelBuildMs: Double,
    val schemaValidateMs: Double,
    val ruleEvalMs: Double,
    val diagnosticFinalizeMs: Double,
    val engineInternalMs: Double,
    val firstMeasuredEngineInternalMs: Double,
    val subsequentEngineInternalMs: Double?,
    val wallClockMs: Double,
    val firstMeasuredWallClockMs: Double,
    val subsequentWallClockMs: Double?,
    /** Sum of all host-timed validate calls (all iterations) for this template. */
    val wallClockTotalMs: Double,
    val bindingOverheadMs: Double,
    val errorMsg: String? = null,
)

private fun errorResult(
    file: String,
    status: String,
    msg: String,
) = TemplateResult(
    file = file,
    status = status,
    sizeBytes = 0,
    resources = 0,
    fatal = 0,
    errors = 0,
    warnings = 0,
    informational = 0,
    diagCount = 0,
    hostModelMs = 0.0,
    firstMeasuredHostModelMs = 0.0,
    subsequentHostModelMs = null,
    modelBuildMs = 0.0,
    schemaValidateMs = 0.0,
    ruleEvalMs = 0.0,
    diagnosticFinalizeMs = 0.0,
    engineInternalMs = 0.0,
    firstMeasuredEngineInternalMs = 0.0,
    subsequentEngineInternalMs = null,
    wallClockMs = 0.0,
    firstMeasuredWallClockMs = 0.0,
    subsequentWallClockMs = null,
    wallClockTotalMs = 0.0,
    bindingOverheadMs = 0.0,
    errorMsg = msg,
)

private class MarkdownInput(
    val allResults: List<TemplateResult>,
    val okResults: List<TemplateResult>,
    val failedResults: List<TemplateResult>,
    val startup: StartupMeasurement,
    val provenance: JsonObject,
    val modelBuild: List<Double>,
    val schemaValidate: List<Double>,
    val ruleEval: List<Double>,
    val diagnosticFinalize: List<Double>,
    val engineInternal: List<Double>,
    val firstEngineInternal: List<Double>,
    val subsequentEngineInternal: List<Double>,
    val wallClock: List<Double>,
    val firstWallClock: List<Double>,
    val subsequentWallClock: List<Double>,
    val hostModel: List<Double>,
    val firstHostModel: List<Double>,
    val subsequentHostModel: List<Double>,
    val overhead: List<Double>,
    val initSamples: List<Double>,
    val subsequentInitSamples: List<Double>,
    val schemaInitSamples: List<Double>,
    val engineInitSamples: List<Double>,
    val totalWallMs: Double,
    val throughputPerSec: Double,
    val engineName: String,
    val iterations: Int,
    val corpusFingerprint: String,
    val corpusFileCount: Int,
)

private fun provenanceStr(
    provenance: JsonObject,
    key: String,
): String = provenance.get(key)?.takeIf { it.isJsonPrimitive }?.asString ?: "unknown"

private fun generateMarkdown(input: MarkdownInput): String =
    buildString {
        appendLine("# cloudformation-validate JVM Benchmark Report - ${input.engineName} engine (DETAILED)\n")
        appendLine("Generated: ${isoNow()}\n")
        appendLine("Corpus fingerprint: `${input.corpusFingerprint}` (${input.corpusFileCount} files)\n")

        appendLine("## Provenance\n")
        appendLine("| Field | Value |\n|---|---|")
        val bindingArtifactVersion =
            input.provenance
                .getAsJsonObject("binding_artifact")
                ?.get("version")
                ?.asString ?: "unknown"
        appendLine("| cloudformation-validate | ${provenanceStr(input.provenance, "cloudformation_validate")} |")
        appendLine("| Binding artifact (jar) | $bindingArtifactVersion |")
        appendLine("| Cargo | ${provenanceStr(input.provenance, "cargo")} |")
        appendLine("| rustc | ${provenanceStr(input.provenance, "rustc")} |")
        appendLine("| Runtime | ${provenanceStr(input.provenance, "runtime")} |")

        appendLine("\n## Summary\n")
        appendLine("| Metric | Value |\n|---|---|")
        appendLine("| Templates | ${input.okResults.size} ok, ${input.failedResults.size} failed, ${input.allResults.size} total |")
        appendLine("| Iterations per template | ${input.iterations} |")
        appendLine("| Total resources | ${input.okResults.sumOf { it.resources }} |")
        appendLine("| Total wall time | ${input.totalWallMs.format(4)} ms |")
        appendLine("| Throughput | ${input.throughputPerSec.format(2)} validations/sec |")
        appendLine("| Detail level | DETAILED |")

        appendLine("\n## Process Startup (single cold sequence)\n")
        appendLine(
            "The consumer validation setup constructed once, then the first validate call on that same engine - the process-cold path a consumer pays before any warmup.\n",
        )
        appendLine("| Metric | Value (ms) |\n|---|---|")
        appendLine("| Startup template | ${input.startup.startupTemplate} |")
        appendLine("| Module load | ${input.startup.moduleLoadMs.format(4)} |")
        appendLine("| Consumer init (${input.startup.consumerInitScope}) | ${input.startup.consumerInitMs.format(4)} |")
        appendLine("| First validation (host) | ${input.startup.first.hostMs.format(4)} |")
        appendLine("| First validation (internal) | ${input.startup.first.internalMs.format(4)} |")
        appendLine("| Internal time-to-first-result | ${input.startup.internalTimeToFirstResultMs.format(4)} |")

        appendLine("\n## Initialization (ms)\n")
        appendLine("Schema init is timed standalone for comparison but is **not additive** for FFI consumers:")
        appendLine("the engine constructor already embeds a SchemaValidator. `init_ms` = engine construction only (actual consumer setup cost).\n")
        appendLine("| Stat | Schema Init (standalone) | Engine Init | Init (engine only) |\n|---|---|---|---|")
        appendLine(
            "| Median | ${medianOf(input.schemaInitSamples).format(4)} | ${medianOf(input.engineInitSamples).format(4)} | ${
                medianOf(
                    input.initSamples,
                ).format(4)
            } |",
        )
        appendLine(
            "| P99 | ${percentileOf(input.schemaInitSamples, 99.0).format(4)} | ${
                percentileOf(
                    input.engineInitSamples,
                    99.0,
                ).format(4)
            } | ${percentileOf(input.initSamples, 99.0).format(4)} |",
        )
        appendLine(
            "| Subsequent median | - | - | ${medianOf(input.subsequentInitSamples).format(4)} |",
        )

        appendLine("\n## Validation Latency (ms, median / p99 / max per template)\n")
        appendLine("host_model = Kotlin-side timer around JvmSemanticModel.parse (includes JNI/UniFFI marshalling).")
        appendLine("wall_clock = Kotlin-side timer around validateDetailed() (includes JNI/UniFFI marshalling).")
        appendLine("engine_internal = Rust-internal `report.performance.validateTotal` (engine work only).")
        appendLine("binding_overhead = median of per-iteration (wall_clock − engine_internal) differences.")
        appendLine("First measured = iteration 1 per template (warm at process level). Subsequent = median of iterations 2..N (empty when N=1).\n")
        appendLine("| Metric | Median | P99 | Max |\n|---|---|---|---|")

        fun row(
            label: String,
            vals: List<Double>,
        ) = "| $label | ${medianOf(vals).format(4)} | ${percentileOf(vals, 99.0).format(4)} | ${maxOf(vals).format(4)} |"
        appendLine(row("First measured host_model", input.firstHostModel))
        appendLine(row("Subsequent host_model", input.subsequentHostModel))
        appendLine(row("First measured engine_internal", input.firstEngineInternal))
        appendLine(row("Subsequent engine_internal", input.subsequentEngineInternal))
        appendLine(row("First measured wall_clock", input.firstWallClock))
        appendLine(row("Subsequent wall_clock", input.subsequentWallClock))
        appendLine(row("host_model (per-template median)", input.hostModel))
        appendLine(row("engine_internal (per-template median)", input.engineInternal))
        appendLine(row("wall_clock (per-template median)", input.wallClock))
        appendLine(row("Model build (rust-internal)", input.modelBuild))
        appendLine(row("Schema validate (rust-internal)", input.schemaValidate))
        appendLine(row("Rule evaluation (rust-internal)", input.ruleEval))
        appendLine(row("Diagnostic finalize (rust-internal)", input.diagnosticFinalize))
        appendLine(row("Binding overhead (wall − internal)", input.overhead))

        appendLine("\n## Diagnostics\n")
        appendLine("| Level | Count |\n|---|---|")
        appendLine("| Fatal | ${input.okResults.sumOf { it.fatal }} |")
        appendLine("| Errors | ${input.okResults.sumOf { it.errors }} |")
        appendLine("| Warnings | ${input.okResults.sumOf { it.warnings }} |")
        appendLine("| Informational | ${input.okResults.sumOf { it.informational }} |")

        appendLine("\n## All Results\n")
        val sorted = input.allResults.sortedByDescending { it.wallClockMs }
        appendLine("| # | Template | Status | Size | Resources | Model (ms) | Schema (ms) | Rules (ms) | Finalize (ms) | Engine (ms) | Wall (ms) | Overhead (ms) | F | E | W | I | Diags |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        sorted.forEachIndexed { i, r ->
            if (r.status == "ok") {
                appendLine(
                    "| ${i + 1} | ${r.file} | ✅ | ${fmtBytes(r.sizeBytes)} | ${r.resources} | ${
                        r.modelBuildMs.format(
                            4,
                        )
                    } | ${r.schemaValidateMs.format(4)} | ${r.ruleEvalMs.format(4)} | ${r.diagnosticFinalizeMs.format(4)} | ${
                        r.engineInternalMs.format(
                            4,
                        )
                    } | ${r.wallClockMs.format(4)} | ${r.bindingOverheadMs.format(4)} | ${r.fatal} | ${r.errors} | ${r.warnings} | ${r.informational} | ${r.diagCount} |",
                )
            } else {
                appendLine("| ${i + 1} | ${r.file} | ❌ ${r.status} | - | - | - | - | - | - | - | - | - | - | 0 | 0 | 0 | 0 | 0 |")
            }
        }

        if (input.failedResults.isNotEmpty()) {
            appendLine("\n## Failures\n")
            for (r in input.failedResults) {
                appendLine("- **${r.file}**: ${r.status} - ${r.errorMsg ?: "unknown"}")
            }
        }
    }

const val formatFlag = "DETAILED"
const val formatDir = "detailed"
