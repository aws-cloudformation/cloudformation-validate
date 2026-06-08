import com.amazonaws.cloudformation.validation.JvmCelEngine
import com.amazonaws.cloudformation.validation.JvmRegoEngine
import com.amazonaws.cloudformation.validation.JvmSemanticModel
import com.amazonaws.cloudformation.validation.SchemaValidator
import com.amazonaws.cloudformation.validation.ValidateConfig
import com.amazonaws.cloudformation.validation.diagnostics.DetailedReport
import com.amazonaws.cloudformation.validation.engine.EngineConfig
import com.amazonaws.cloudformation.validation.gson.buildBindingsGson
import com.amazonaws.cloudformation.validation.rules.RuleFilterConfig
import com.amazonaws.cloudformation.validation.rules.Severity
import com.amazonaws.cloudformation.validation.templatemodel.PseudoParameterOverrides
import com.amazonaws.cloudformation.validation.version
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.math.sqrt

fun main(args: Array<String>) {
    if (args.any { it == "-h" || it == "--help" }) {
        System.err.println("Usage: gradle run --args=\"[TEMPLATE|DIR] [--engine rego|cel] [--iterations N]\"")
        return
    }

    val defaultTemplateDir = File(System.getProperty("user.dir")).resolve("../../resources/templates").canonicalPath
    val engineFlag = argValue(args, "--engine") ?: "rego"
    val iterations = (argValue(args, "--iterations")?.toIntOrNull() ?: 20).coerceAtLeast(1)

    val templateDir = run {
        val flagsWithValues = setOf("--engine", "--iterations")
        var i = 0
        while (i < args.size) {
            if (flagsWithValues.contains(args[i])) {
                i += 2; continue
            }
            if (!args[i].startsWith("-")) return@run args[i]
            i++
        }
        defaultTemplateDir
    }

    val templates = collectFiles(File(templateDir))
    if (templates.isEmpty()) {
        System.err.println("No templates found in $templateDir")
        return
    }

    System.err.println("Benchmarking ${templates.size} templates, $iterations iterations, engine=$engineFlag, format=$formatFlag")


    // Measure JNI native library load time. The first call to any UniFFI-generated function
    // triggers Native.register() for the Rust shared library. Use the lightweight version()
    // function to isolate library loading from schema/engine construction costs.
    val moduleLoadStart = System.nanoTime()
    version()
    val moduleLoadMs = (System.nanoTime() - moduleLoadStart) / 1_000_000.0

    fun newEngine(): Any = when (engineFlag) {
        "cel" -> JvmCelEngine(engineConfig())
        else -> JvmRegoEngine(engineConfig())
    }

    val schemaInitSamples = mutableListOf<Double>()
    val engineInitSamples = mutableListOf<Double>()
    repeat(iterations) {
        val t0 = System.nanoTime()
        SchemaValidator()
        schemaInitSamples.add((System.nanoTime() - t0) / 1_000_000.0)

        val t1 = System.nanoTime()
        val created = newEngine()
        engineInitSamples.add((System.nanoTime() - t1) / 1_000_000.0)
        if (created is AutoCloseable) created.close()
    }
    val initSamples = schemaInitSamples.zip(engineInitSamples) { s, e -> s + e }
    // cold_init_ms includes JNI module load + first schema init + first engine init.
    val coldInitMs = moduleLoadMs + initSamples[0]
    val warmInitSamples = if (initSamples.size > 1) initSamples.drop(1) else initSamples

    val engine: Any = newEngine()

    val reportDir = File(System.getProperty("user.dir")).resolve("../reports/$engineFlag").also { it.mkdirs() }
    val jsonDir = reportDir.resolve("json_$formatDir").also { it.mkdirs() }

    // Warm up JIT + UniFFI vtables so the first timed call doesn't pay codegen costs.
    if (templates.isNotEmpty()) {
        val warmupBytes = templates[0].readBytes()
        try {
            JvmSemanticModel.parse(warmupBytes)
        } catch (_: Exception) {
        }
        try {
            validateDetailed(engine, warmupBytes, validateConfig(), templates[0].name)
        } catch (_: Exception) {
        }
    }

    // Collected during the timed loop and flushed AFTER wall-clock stops. Each entry holds
    // enough context to re-run a validate_full_json() call post-benchmark to produce the
    // full-report JSON, matching what the native and WASM harnesses write.
    val pendingReports = mutableListOf<PendingReport>()

    val results = mutableListOf<TemplateResult>()
    val benchStart = System.nanoTime()

    for (tpl in templates) {
        val rel = File(templateDir).toPath().relativize(tpl.toPath()).toString().ifEmpty { tpl.name }
        System.err.print("  $rel")

        val sizeBytes = try {
            tpl.length().toInt()
        } catch (e: Exception) {
            results.add(errorResult(rel, "read_error", e.message ?: "unknown"))
            continue
        }
        val bytes = tpl.readBytes()
        val iterModelBuild = mutableListOf<Double>()
        val iterSchemaValidate = mutableListOf<Double>()
        val iterRuleEval = mutableListOf<Double>()
        val iterFinalize = mutableListOf<Double>()
        // Host-timed model parse — Kotlin-side nanoTime around JvmSemanticModel.parse.
        // Includes JNI dispatch + UniFFI marshalling of the parse call.
        val iterHostModel = mutableListOf<Double>()
        val iterEngineInternal = mutableListOf<Double>()
        // wall_clock = Kotlin-side nanoTime around validateDetailed() — includes JNI dispatch,
        // ByteArray→Rust Vec<u8> copy, UniFFI DetailedReport decoding.
        val iterWallClock = mutableListOf<Double>()
        var lastReport: DetailedReport? = null
        var failed = false

        repeat(iterations) { i ->
            if (failed) return@repeat
            try {
                // Host-timed model parse (standalone, no I/O — bytes pre-read).
                val tm0 = System.nanoTime()
                val parsed = JvmSemanticModel.parse(bytes)
                iterHostModel.add((System.nanoTime() - tm0) / 1_000_000.0)
                try {
                    (parsed as? AutoCloseable)?.close()
                } catch (_: Exception) {
                }

                val t0 = System.nanoTime()
                val report = validateDetailed(engine, bytes, validateConfig(), rel)
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
        val coldEngineInternalMs = iterEngineInternal[0]
        val warmEngineInternalMs = if (iterations > 1) medianOf(
            iterEngineInternal.subList(
                1, iterEngineInternal.size
            )
        ) else coldEngineInternalMs
        val medianEngineInternal = medianOf(iterEngineInternal)
        val coldWallClockMs = iterWallClock[0]
        val warmWallClockMs =
            if (iterations > 1) medianOf(iterWallClock.subList(1, iterWallClock.size)) else coldWallClockMs
        val medianWallClock = medianOf(iterWallClock)
        val coldHostModelMs = iterHostModel[0]
        val warmHostModelMs =
            if (iterations > 1) medianOf(iterHostModel.subList(1, iterHostModel.size)) else coldHostModelMs
        val medianHostModel = medianOf(iterHostModel)
        val bindingOverheadMs = round4(medianWallClock - medianEngineInternal)

        val jsonStem = rel.replace("/", "_").replace(Regex("\\.(yaml|json|yml)$"), "")
        fun iterObj(
            hostModel: Double,
            modelBuild: Double,
            schemaValidate: Double,
            ruleEval: Double,
            finalize: Double,
            engineInternal: Double,
            wallClock: Double
        ) = JsonObject().apply {
            addProperty("hostModelMs", round4(hostModel))
            addProperty("modelBuildMs", round4(modelBuild))
            addProperty("schemaValidateMs", round4(schemaValidate))
            addProperty("ruleEvaluationMs", round4(ruleEval))
            addProperty("diagnosticFinalizeMs", round4(finalize))
            addProperty("engineInternalMs", round4(engineInternal))
            addProperty("wallClockMs", round4(wallClock))
        }

        val metrics = JsonObject().apply {
            addProperty("iterations", iterations)
            add(
                "firstIteration", iterObj(
                    iterHostModel[0],
                    iterModelBuild[0],
                    iterSchemaValidate[0],
                    iterRuleEval[0],
                    iterFinalize[0],
                    coldEngineInternalMs,
                    coldWallClockMs
                )
            )
            add(
                "steadyState", iterObj(
                    warmHostModelMs,
                    if (iterations > 1) medianOf(iterModelBuild.drop(1)) else iterModelBuild[0],
                    if (iterations > 1) medianOf(iterSchemaValidate.drop(1)) else iterSchemaValidate[0],
                    if (iterations > 1) medianOf(iterRuleEval.drop(1)) else iterRuleEval[0],
                    if (iterations > 1) medianOf(iterFinalize.drop(1)) else iterFinalize[0],
                    warmEngineInternalMs,
                    warmWallClockMs
                )
            )
            addProperty("bindingOverheadMs", bindingOverheadMs)
        }
        // Deferred: serialize the last report post-benchmark via Gson.
        pendingReports.add(PendingReport(jsonDir.resolve("$jsonStem.json"), rel, report, metrics))

        val tr = TemplateResult(
            file = rel, status = "ok", sizeBytes = sizeBytes,
            resources = report.metadata.resourcesScanned.toInt(),
            fatal = report.metadata.counts.fatal.toInt(),
            errors = report.metadata.counts.errors.toInt(),
            warnings = report.metadata.counts.warnings.toInt(),
            informational = report.metadata.counts.informational.toInt(),
            diagCount = report.diagnostics.size,
            hostModelMs = medianHostModel,
            coldHostModelMs = coldHostModelMs,
            warmHostModelMs = warmHostModelMs,
            modelBuildMs = medianOf(iterModelBuild),
            schemaValidateMs = medianOf(iterSchemaValidate),
            ruleEvalMs = medianOf(iterRuleEval),
            diagnosticFinalizeMs = medianOf(iterFinalize),
            engineInternalMs = medianEngineInternal,
            coldEngineInternalMs = coldEngineInternalMs,
            warmEngineInternalMs = warmEngineInternalMs,
            wallClockMs = medianWallClock,
            coldWallClockMs = coldWallClockMs,
            warmWallClockMs = warmWallClockMs,
            bindingOverheadMs = bindingOverheadMs,
        )
        System.err.println("  engine=${tr.engineInternalMs.format(4)}ms  wall=${tr.wallClockMs.format(4)}ms  ${tr.errors}E ${tr.warnings}W ${tr.informational}I")
        results.add(tr)
    }

    val totalWallMs = (System.nanoTime() - benchStart) / 1_000_000.0

    // Flush per-template JSON dumps AFTER wall-clock stops.
    // Uses the report captured during the last timed iteration — no re-validation.
    val dumpGson = buildBindingsGson(prettyPrinting = true)
    for (pr in pendingReports) {
        try {
            val reportElement = dumpGson.toJsonTree(pr.report).asJsonObject
            reportElement.addProperty("engine", engineFlag)
            reportElement.addProperty("binding", "jvm")
            reportElement.addProperty("detailLevel", formatFlag)
            reportElement.add("benchmarkMetrics", pr.metrics)
            pr.dest.writeText(dumpGson.toJson(reportElement))
        } catch (_: Exception) { /* dump is best-effort */
        }
    }

    val ok = results.filter { it.status == "ok" }
    val failures = results.filter { it.status != "ok" }

    val modelBuildVec = ok.map { it.modelBuildMs }
    val schemaValidateVec = ok.map { it.schemaValidateMs }
    val ruleEvalVec = ok.map { it.ruleEvalMs }
    val finalizeVec = ok.map { it.diagnosticFinalizeMs }
    val engineInternalVec = ok.map { it.engineInternalMs }
    val coldEngineInternalVec = ok.map { it.coldEngineInternalMs }
    val warmEngineInternalVec = ok.map { it.warmEngineInternalMs }
    val wallClockVec = ok.map { it.wallClockMs }
    val coldWallClockVec = ok.map { it.coldWallClockMs }
    val warmWallClockVec = ok.map { it.warmWallClockMs }
    val hostModelVec = ok.map { it.hostModelMs }
    val coldHostModelVec = ok.map { it.coldHostModelMs }
    val warmHostModelVec = ok.map { it.warmHostModelMs }
    val overheadVec = ok.map { it.bindingOverheadMs }

    val throughputPerSec = if (totalWallMs > 0) ok.size * iterations / (totalWallMs / 1000.0) else 0.0

    val (corpusFingerprint, corpusFileCount) = computeCorpusFingerprint(File(templateDir))
    val runFingerprint = sha256Hex("$corpusFingerprint|$engineFlag|$formatFlag|$iterations")

    val aggregateGson = buildBindingsGson(prettyPrinting = true)

    fun statsToJsonObject(vals: List<Double>): JsonObject {
        val obj = JsonObject()
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

    val perfObj = JsonObject().apply {
        addProperty("module_load_ms", round4(moduleLoadMs))
        add("init_ms", statsToJsonObject(initSamples))
        addProperty("cold_init_ms", round4(coldInitMs))
        add("warm_init_ms", statsToJsonObject(warmInitSamples))
        add("schema_init_ms", statsToJsonObject(schemaInitSamples))
        add("engine_init_ms", statsToJsonObject(engineInitSamples))
        addProperty("total_wall_ms", round4(totalWallMs))
        addProperty("throughput_per_sec", round4(throughputPerSec))
        add("model_build_ms", statsToJsonObject(modelBuildVec))
        add("schema_validate_ms", statsToJsonObject(schemaValidateVec))
        add("rule_evaluation_ms", statsToJsonObject(ruleEvalVec))
        add("diagnostic_finalize_ms", statsToJsonObject(finalizeVec))
        add("engine_internal_ms", statsToJsonObject(engineInternalVec))
        add("cold_engine_internal_ms", statsToJsonObject(coldEngineInternalVec))
        add("warm_engine_internal_ms", statsToJsonObject(warmEngineInternalVec))
        add("wall_clock_ms", statsToJsonObject(wallClockVec))
        add("cold_wall_clock_ms", statsToJsonObject(coldWallClockVec))
        add("warm_wall_clock_ms", statsToJsonObject(warmWallClockVec))
        add("host_model_ms", statsToJsonObject(hostModelVec))
        add("cold_host_model_ms", statsToJsonObject(coldHostModelVec))
        add("warm_host_model_ms", statsToJsonObject(warmHostModelVec))
        add("binding_overhead_ms", statsToJsonObject(overheadVec))
    }

    val diagObj = JsonObject().apply {
        addProperty("total_fatal", ok.sumOf { it.fatal })
        addProperty("total_errors", ok.sumOf { it.errors })
        addProperty("total_warnings", ok.sumOf { it.warnings })
        addProperty("total_informational", ok.sumOf { it.informational })
    }

    val failuresArr = JsonArray().apply {
        for (r in failures) {
            add(JsonObject().apply {
                addProperty("file", r.file)
                addProperty("status", r.status)
                addProperty("error", r.errorMsg ?: "unknown")
            })
        }
    }

    val aggregateObj = JsonObject().apply {
        addProperty("timestamp", isoNow())
        addProperty("engine", engineFlag)
        addProperty("binding", "jvm")
        addProperty("detail_level", formatFlag)
        addProperty("template_dir", templateDir)
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
    reportDir.resolve("aggregate_$formatDir.json").writeText(aggregateGson.toJson(aggregateObj))

    val md = generateMarkdown(
        results,
        ok,
        failures,
        modelBuildVec,
        schemaValidateVec,
        ruleEvalVec,
        finalizeVec,
        engineInternalVec,
        coldEngineInternalVec,
        warmEngineInternalVec,
        wallClockVec,
        coldWallClockVec,
        warmWallClockVec,
        hostModelVec,
        coldHostModelVec,
        warmHostModelVec,
        overheadVec,
        initSamples,
        schemaInitSamples,
        engineInitSamples,
        totalWallMs,
        throughputPerSec,
        engineFlag,
        iterations,
        corpusFingerprint,
        corpusFileCount
    )
    reportDir.resolve("report_$formatDir.md").writeText(md)

    System.err.println("\nBenchmark complete: ${ok.size} ok, ${failures.size} failed ($iterations iterations/template)")
    System.err.println(
        "schema_init (median): ${medianOf(schemaInitSamples).format(4)}ms  engine_init (median): ${
            medianOf(
                engineInitSamples
            ).format(4)
        }ms"
    )
    System.err.println(
        "engine_internal (median): median=${medianOf(engineInternalVec).format(4)}ms p99=${
            percentileOf(
                engineInternalVec, 99.0
            ).format(4)
        }ms max=${maxOf(engineInternalVec).format(4)}ms"
    )
    System.err.println(
        "wall_clock     (median): median=${medianOf(wallClockVec).format(4)}ms p99=${
            percentileOf(
                wallClockVec, 99.0
            ).format(4)
        }ms max=${maxOf(wallClockVec).format(4)}ms"
    )
    System.err.println("Throughput: ${throughputPerSec.format(2)} validations/sec")
    System.err.println("Corpus fingerprint: $corpusFingerprint ($corpusFileCount files)")
    System.err.println("Reports written to $reportDir")
}

private fun computeCorpusFingerprint(root: File): Pair<String, Int> {
    // MUST mirror Rust and TS: SHA-256 over sorted "relpath\tsha256(content)\n" lines.
    val files = collectFiles(root)
    val outer = MessageDigest.getInstance("SHA-256")
    for (f in files) {
        val content = f.readBytes()
        val fileHash = sha256Hex(content)
        val rel = root.toPath().relativize(f.toPath()).toString().ifEmpty { f.name }
        outer.update("$rel\t$fileHash\n".toByteArray(Charsets.UTF_8))
    }
    return outer.digest().joinToString("") { "%02x".format(it) } to files.size
}

private fun sha256Hex(data: String): String = sha256Hex(data.toByteArray(Charsets.UTF_8))
private fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }


private fun argValue(args: Array<String>, flag: String): String? {
    val idx = args.indexOf(flag)
    return if (idx >= 0 && idx + 1 < args.size) args[idx + 1] else null
}

private fun validateDetailed(
    engine: Any, template: ByteArray, config: ValidateConfig, filePath: String
): DetailedReport = when (engine) {
    is JvmCelEngine -> engine.validateDetailed(template, config, filePath)
    is JvmRegoEngine -> engine.validateDetailed(template, config, filePath)
    else -> throw IllegalArgumentException("Unknown engine type")
}

fun engineConfig() = EngineConfig(customRules = listOf(), guardRules = listOf())
fun validateConfig() = ValidateConfig(
    include = RuleFilterConfig(),
    exclude = RuleFilterConfig(),
    severityLevel = Severity.DEBUG,
    parameterOverrides = mapOf(),
    pseudoParameterOverrides = PseudoParameterOverrides(),
    strict = false,
    includeEngineRules = true,
)

private data class PendingReport(val dest: File, val rel: String, val report: DetailedReport, val metrics: JsonObject)

private val TEMPLATE_EXTENSIONS = setOf("yaml", "yml", "json")

private fun collectFiles(fileOrDir: File): List<File> {
    if (fileOrDir.isFile) return listOf(fileOrDir)
    return fileOrDir.walkTopDown().filter { it.isFile && it.extension.lowercase() in TEMPLATE_EXTENSIONS }.toList()
        .sortedBy { it.path }
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

private fun percentileOf(vals: List<Double>, pct: Double): Double {
    if (vals.isEmpty()) return 0.0
    val s = vals.sorted()
    val rank = (pct / 100.0) * (s.size - 1)
    val lo = rank.toInt()
    val hi = (lo + 1).coerceAtMost(s.size - 1)
    val frac = rank - lo
    return s[lo] + frac * (s[hi] - s[lo])
}

private fun round4(v: Double): Double = Math.round(v * 10000.0) / 10000.0
private fun Double.format(decimals: Int): String = "%.${decimals}f".format(this)
private fun isoNow(): String =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC).format(Instant.now())

private fun fmtBytes(n: Int): String = when {
    n >= 1_048_576 -> "${"%.1f".format(n / 1_048_576.0)} MB"
    n >= 1024 -> "${"%.1f".format(n / 1024.0)} KB"
    else -> "$n B"
}


private data class TemplateResult(
    val file: String, val status: String, val sizeBytes: Int,
    val resources: Int, val fatal: Int, val errors: Int,
    val warnings: Int, val informational: Int, val diagCount: Int,
    val hostModelMs: Double, val coldHostModelMs: Double, val warmHostModelMs: Double,
    val modelBuildMs: Double, val schemaValidateMs: Double, val ruleEvalMs: Double,
    val diagnosticFinalizeMs: Double,
    val engineInternalMs: Double, val coldEngineInternalMs: Double, val warmEngineInternalMs: Double,
    val wallClockMs: Double, val coldWallClockMs: Double, val warmWallClockMs: Double,
    val bindingOverheadMs: Double, val errorMsg: String? = null,
)

private fun errorResult(file: String, status: String, msg: String) = TemplateResult(
    file = file, status = status, sizeBytes = 0, resources = 0, fatal = 0, errors = 0,
    warnings = 0, informational = 0, diagCount = 0,
    hostModelMs = 0.0, coldHostModelMs = 0.0, warmHostModelMs = 0.0,
    modelBuildMs = 0.0,
    schemaValidateMs = 0.0, ruleEvalMs = 0.0, diagnosticFinalizeMs = 0.0,
    engineInternalMs = 0.0, coldEngineInternalMs = 0.0, warmEngineInternalMs = 0.0,
    wallClockMs = 0.0, coldWallClockMs = 0.0, warmWallClockMs = 0.0,
    bindingOverheadMs = 0.0, errorMsg = msg,
)

private fun generateMarkdown(
    allResults: List<TemplateResult>, okResults: List<TemplateResult>, failedResults: List<TemplateResult>,
    modelBuild: List<Double>, schemaValidate: List<Double>, ruleEval: List<Double>,
    diagnosticFinalize: List<Double>,
    engineInternal: List<Double>, coldEngineInternal: List<Double>, warmEngineInternal: List<Double>,
    wallClock: List<Double>, coldWallClock: List<Double>, warmWallClock: List<Double>,
    hostModel: List<Double>, coldHostModel: List<Double>, warmHostModel: List<Double>,
    overhead: List<Double>,
    initSamples: List<Double>, schemaInitSamples: List<Double>, engineInitSamples: List<Double>,
    totalWallMs: Double, throughputPerSec: Double, engineName: String, iterations: Int,
    corpusFingerprint: String, corpusFileCount: Int,
): String = buildString {
    appendLine("# cloudformation-validate JVM Benchmark Report — $engineName engine (DETAILED)\n")
    appendLine("Generated: ${isoNow()}\n")
    appendLine("Corpus fingerprint: `$corpusFingerprint` ($corpusFileCount files)\n")

    appendLine("## Summary\n")
    appendLine("| Metric | Value |\n|---|---|")
    appendLine("| Templates | ${okResults.size} ok, ${failedResults.size} failed, ${allResults.size} total |")
    appendLine("| Iterations per template | $iterations |")
    appendLine("| Total resources | ${okResults.sumOf { it.resources }} |")
    appendLine("| Total wall time | ${totalWallMs.format(4)} ms |")
    appendLine("| Throughput | ${throughputPerSec.format(2)} validations/sec |")
    appendLine("| Detail level | DETAILED |")

    appendLine("\n## Initialization (ms)\n")
    appendLine("| Stat | Schema Init | Engine Init | Combined |\n|---|---|---|---|")
    appendLine(
        "| Median | ${medianOf(schemaInitSamples).format(4)} | ${medianOf(engineInitSamples).format(4)} | ${
            medianOf(
                initSamples
            ).format(4)
        } |"
    )
    appendLine(
        "| P99 | ${percentileOf(schemaInitSamples, 99.0).format(4)} | ${
            percentileOf(
                engineInitSamples, 99.0
            ).format(4)
        } | ${percentileOf(initSamples, 99.0).format(4)} |"
    )
    appendLine(
        "| Max | ${maxOf(schemaInitSamples).format(4)} | ${maxOf(engineInitSamples).format(4)} | ${
            maxOf(
                initSamples
            ).format(4)
        } |"
    )

    appendLine("\n## Validation Latency (ms, median / p99 / max per template)\n")
    appendLine("host_model = Kotlin-side timer around JvmSemanticModel.parse (includes JNI/UniFFI marshalling).")
    appendLine("wall_clock = Kotlin-side timer around validateDetailed() (includes JNI/UniFFI marshalling).")
    appendLine("engine_internal = Rust-internal `report.performance.validateTotal` (engine work only).\n")
    appendLine("| Metric | Median | P99 | Max |\n|---|---|---|---|")
    fun row(label: String, vals: List<Double>) =
        "| $label | ${medianOf(vals).format(4)} | ${percentileOf(vals, 99.0).format(4)} | ${maxOf(vals).format(4)} |"
    appendLine(row("Cold host_model (first iter)", coldHostModel))
    appendLine(row("Warm host_model (steady)", warmHostModel))
    appendLine(row("Cold engine_internal (first iter)", coldEngineInternal))
    appendLine(row("Warm engine_internal (steady)", warmEngineInternal))
    appendLine(row("Cold wall_clock (first iter)", coldWallClock))
    appendLine(row("Warm wall_clock (steady)", warmWallClock))
    appendLine(row("host_model (per-template median)", hostModel))
    appendLine(row("engine_internal (per-template median)", engineInternal))
    appendLine(row("wall_clock (per-template median)", wallClock))
    appendLine(row("Model build (rust-internal)", modelBuild))
    appendLine(row("Schema validate (rust-internal)", schemaValidate))
    appendLine(row("Rule evaluation (rust-internal)", ruleEval))
    appendLine(row("Diagnostic finalize (rust-internal)", diagnosticFinalize))
    appendLine(row("Binding overhead (wall − internal)", overhead))

    appendLine("\n## Diagnostics\n")
    appendLine("| Level | Count |\n|---|---|")
    appendLine("| Fatal | ${okResults.sumOf { it.fatal }} |")
    appendLine("| Errors | ${okResults.sumOf { it.errors }} |")
    appendLine("| Warnings | ${okResults.sumOf { it.warnings }} |")
    appendLine("| Informational | ${okResults.sumOf { it.informational }} |")

    appendLine("\n## All Results\n")
    val sorted = allResults.sortedByDescending { it.wallClockMs }
    appendLine("| # | Template | Status | Size | Resources | Model (ms) | Schema (ms) | Rules (ms) | Finalize (ms) | Engine (ms) | Wall (ms) | Overhead (ms) | F | E | W | I | Diags |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    sorted.forEachIndexed { i, r ->
        if (r.status == "ok") {
            appendLine(
                "| ${i + 1} | ${r.file} | ✅ | ${fmtBytes(r.sizeBytes)} | ${r.resources} | ${
                    r.modelBuildMs.format(
                        4
                    )
                } | ${r.schemaValidateMs.format(4)} | ${r.ruleEvalMs.format(4)} | ${r.diagnosticFinalizeMs.format(4)} | ${
                    r.engineInternalMs.format(
                        4
                    )
                } | ${r.wallClockMs.format(4)} | ${r.bindingOverheadMs.format(4)} | ${r.fatal} | ${r.errors} | ${r.warnings} | ${r.informational} | ${r.diagCount} |"
            )
        } else {
            appendLine("| ${i + 1} | ${r.file} | ❌ ${r.status} | - | - | - | - | - | - | - | - | - | - | 0 | 0 | 0 | 0 | 0 |")
        }
    }

    if (failedResults.isNotEmpty()) {
        appendLine("\n## Failures\n")
        for (r in failedResults) {
            appendLine("- **${r.file}**: ${r.status} — ${r.errorMsg ?: "unknown"}")
        }
    }
}

const val formatFlag = "DETAILED"
const val formatDir = "detailed"
