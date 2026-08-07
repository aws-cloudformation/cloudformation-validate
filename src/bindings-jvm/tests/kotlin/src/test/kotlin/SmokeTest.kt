import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows
import software.amazon.cloudformation.validate.*
import software.amazon.cloudformation.validate.datasource.AdditionalSchemaSource
import software.amazon.cloudformation.validate.diagnostics.*
import software.amazon.cloudformation.validate.engine.*
import software.amazon.cloudformation.validate.gson.buildBindingsGson
import software.amazon.cloudformation.validate.rules.*
import software.amazon.cloudformation.validate.schemavalidator.SchemaValidatorConfig
import java.io.File

class SmokeTest {
    private fun templateFile(rel: String): File = File(templatesRoot, rel)
    private fun templateBytes(rel: String): ByteArray = templateFile(rel).readBytes()
    private fun loadRule(filename: String): String = File(rulesDir, filename).readText()

    private val templateWithOverlayProperty = """
        Resources:
          Function:
            Type: AWS::Lambda::Function
            Properties:
              Code:
                ZipFile: "exports.handler = async () => {};"
              Role: arn:aws:iam::123456789012:role/lambda-role
              Runtime: nodejs18.x
              Handler: index.handler
              TestForOverride: enabled
    """.trimIndent().toByteArray()

    private val lambdaOverlaySchema = """{
        "typeName": "AWS::Lambda::Function",
        "properties": {"TestForOverride": {"type": "string"}}
    }""".trimIndent()

    private fun defaultConfig() = ValidateConfig(severityLevel = Severity.DEBUG)

    private fun celCustomConfig() = EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "cel_custom.json", content = loadRule("cel_custom.json"))),
    )

    private fun regoCustomConfig() = EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "rego_custom.rego", content = loadRule("rego_custom.rego"))),
    )

    private fun guardConfig() = EngineConfig(
        guardRules = listOf(ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")))
    )

    private fun celCombinedConfig() = EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "cel_custom.json", content = loadRule("cel_custom.json"))),
        guardRules = listOf(ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")))
    )

    private fun regoCombinedConfig() = EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "rego_custom.rego", content = loadRule("rego_custom.rego"))),
        guardRules = listOf(ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")))
    )

    // ── version ──────────────────────────────────────────────────────────────

    private fun readWorkspaceVersion(): String {
        val cargoToml = File(resourcesRoot.parentFile, "Cargo.toml")
        var inWorkspacePackage = false
        for (line in cargoToml.readLines()) {
            val trimmed = line.trim()
            if (trimmed == "[workspace.package]") {
                inWorkspacePackage = true
                continue
            }
            if (inWorkspacePackage && trimmed.startsWith("[")) {
                break
            }
            if (inWorkspacePackage && trimmed.startsWith("version = ")) {
                val value = trimmed.removePrefix("version = ").trim()
                require(value.startsWith("\"") && value.endsWith("\"")) {
                    "malformed version line in ${cargoToml.path}: $line"
                }
                return value.substring(1, value.length - 1)
            }
        }
        error("missing 'version = ' under [workspace.package] in ${cargoToml.path}")
    }

    @Test
    fun versionReturnsCrateVersionFromWorkspaceCargoToml() {
        assertEquals(readWorkspaceVersion(), version())
    }

    // ── Engine construction ──────────────────────────────────────────────────

    @Test
    fun celEngineReportsNameCel() {
        assertEquals("cel", JvmCelEngine(EngineConfig()).engineName())
    }

    @Test
    fun regoEngineReportsNameRego() {
        assertEquals("rego", JvmRegoEngine(EngineConfig()).engineName())
    }

    @Test
    fun additionalSchemasApplyThroughThePublicConfigOnBothEngines() {
        val config = EngineConfig(
            schemaValidatorConfig = SchemaValidatorConfig(
                additionalSchemas = listOf(AdditionalSchemaSource(typeName = null, schema = lambdaOverlaySchema)),
            ),
        )
        val celBaseline = JvmCelEngine(EngineConfig()).validateStandard(
            templateWithOverlayProperty,
            defaultConfig(),
            "overlay.yaml",
        )
        val regoBaseline = JvmRegoEngine(EngineConfig()).validateStandard(
            templateWithOverlayProperty,
            defaultConfig(),
            "overlay.yaml",
        )
        assertTrue(celBaseline.diagnostics.any { it.ruleId == "F3002" }, "CEL baseline must report the property")
        assertTrue(regoBaseline.diagnostics.any { it.ruleId == "F3002" }, "Rego baseline must report the property")

        val cel = JvmCelEngine(config).validateStandard(templateWithOverlayProperty, defaultConfig(), "overlay.yaml")
        val rego = JvmRegoEngine(config).validateStandard(templateWithOverlayProperty, defaultConfig(), "overlay.yaml")
        assertFalse(cel.diagnostics.any { it.ruleId == "F3002" }, "CEL config must apply the overlay")
        assertFalse(rego.diagnostics.any { it.ruleId == "F3002" }, "Rego config must apply the overlay")
    }

    @Test
    fun additionalSchemaFileHelperLoadsTheSchemaAndOptionalTypeName() {
        val schemaFile = File.createTempFile("cloudformation-validate-overlay", ".json")
        try {
            schemaFile.writeText(lambdaOverlaySchema)
            val source = fileToAdditionalSchemaSource(schemaFile, "AWS::Lambda::Function")
            assertEquals("AWS::Lambda::Function", source.typeName)
            assertEquals(lambdaOverlaySchema, source.schema)
        } finally {
            schemaFile.delete()
        }
    }

    // ── SchemaValidator ──────────────────────────────────────────────────────

    @Test
    fun schemaValidatorExposesSchemasAndRules() {
        val sv = JvmSchemaValidator(SchemaValidatorConfig())
        assertTrue(sv.schemaCount() > 0u, "schema count must be positive")
        val rules = sv.listRules()
        assertTrue(rules.isNotEmpty(), "schema validator must have rules")
        assertTrue(rules[0].id.isNotEmpty(), "first rule must have an id")
    }

    // ── listRules ────────────────────────────────────────────────────────────

    @Test
    fun celListRulesSortedById() {
        val ids = CEL.listRules().map { it.id }
        assertTrue(ids.isNotEmpty(), "rule list must not be empty")
        assertEquals(ids, ids.sorted(), "rules must be sorted by id")
    }

    @Test
    fun regoListRulesSortedById() {
        val ids = REGO.listRules().map { it.id }
        assertTrue(ids.isNotEmpty(), "rule list must not be empty")
        assertEquals(ids, ids.sorted(), "rules must be sorted by id")
    }

    @Test
    fun celAndRegoListIdenticalRules() {
        assertEquals(
            gson.toJson(CEL.listRules()),
            gson.toJson(REGO.listRules()),
            "CEL and Rego must list identical rules"
        )
    }

    // ── SemanticModel ────────────────────────────────────────────────────────

    @Test
    fun semanticModelParsesFormatVersionAndResources() {
        val model = JvmSemanticModel.parse(templateBytes("good/minimal.yaml"))
        assertEquals("2010-09-09", model.formatVersion())
        assertTrue(model.resources().containsKey("IamPipeline"), "must contain IamPipeline resource")
    }

    @Test
    fun semanticModelParsesDescriptionConditionsOutputs() {
        val model = JvmSemanticModel.parse(templateBytes("good/generic.yaml"))
        assertEquals("A sample template", model.description())
        assertTrue(model.conditions().contains("ProdVolumeSize"))
        assertTrue(model.outputs().containsKey("ElasticIP"))
    }

    @Test
    fun semanticModelRejectsMalformedYaml() {
        assertThrows<ValidationException> { JvmSemanticModel.parse(templateBytes("malformed.yaml")) }
    }

    @Test
    fun semanticModelMinimalHasNoConditionsOrTransforms() {
        val model = JvmSemanticModel.parse(templateBytes("good/minimal.yaml"))
        assertTrue(model.transforms().isEmpty(), "minimal template must have no transforms")
        assertTrue(model.conditions().isEmpty(), "minimal template must have no conditions")
    }

    // ── Invalid input ────────────────────────────────────────────────────────

    @Test
    fun celReturnsF1101ForEmptyTemplate() {
        val report = CEL.validateStandard(templateFile("empty.yaml"), defaultConfig())
        assertEquals("ERROR", report.status.name)
        assertEquals("F1101", report.diagnostics[0].ruleId)
        assertEquals(Severity.FATAL, report.diagnostics[0].severity)
    }

    @Test
    fun regoReturnsF1101ForEmptyTemplate() {
        val report = REGO.validateStandard(templateFile("empty.yaml"), defaultConfig())
        assertEquals("ERROR", report.status.name)
        assertEquals("F1101", report.diagnostics[0].ruleId)
        assertEquals(Severity.FATAL, report.diagnostics[0].severity)
    }

    // ── Custom rules: 1 file, 1 rule ──────────────────────────────────────

    @Test
    fun customRuleListRulesAndValidateMatchBetweenEngines() {
        val cel = JvmCelEngine(celCustomConfig())
        val rego = JvmRegoEngine(regoCustomConfig())
        val badTemplate = "bad/invalid_deletion_policy.yaml"

        for ((name, engine) in listOf("cel" to cel as Any, "rego" to rego as Any)) {
            val report = when (engine) {
                is JvmCelEngine -> engine.validateStandard(templateBytes(badTemplate), defaultConfig(), badTemplate)
                is JvmRegoEngine -> engine.validateStandard(templateBytes(badTemplate), defaultConfig(), badTemplate)
                else -> error("")
            }
            val d = report.diagnostics.find { it.ruleId == "CUSTOM001" } ?: fail("$name: CUSTOM001 diagnostic must fire")
            assertEquals(Severity.ERROR, d.severity, "$name: diagnostic severity")
            assertEquals("Bucket", d.entity?.logicalId, "$name: entity logicalId")
            assertEquals("AWS::S3::Bucket", d.entity?.resourceType, "$name: entity resourceType")
        }

        val baselineCount = CEL.listRules().size
        for ((name, engine) in listOf("cel" to cel as Any, "rego" to rego as Any)) {
            val rules = when (engine) { is JvmCelEngine -> engine.listRules(); is JvmRegoEngine -> engine.listRules(); else -> error("") }
            val c = rules.find { it.id == "CUSTOM001" } ?: fail("$name: CUSTOM001 must exist")
            assertEquals(Severity.ERROR, c.severity, "$name: CUSTOM001 severity")
            assertEquals(RuleOrigin.CUSTOM, c.origin, "$name: CUSTOM001 origin")
            assertEquals("S3 bucket must have encryption configured", c.description, "$name: CUSTOM001 description")
            assertEquals(baselineCount, rules.count { it.origin != RuleOrigin.CUSTOM }, "$name: must not pollute builtins")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "custom: listRules must be identical")
    }

    // ── Guard rules: 1 file, 1 rule ─────────────────────────────────────────

    @Test
    fun guardRuleListRulesAndValidateMatchBetweenEngines() {
        val cel = JvmCelEngine(guardConfig())
        val rego = JvmRegoEngine(guardConfig())
        val badTemplate = "bad/invalid_deletion_policy.yaml"

        val baselineCount = CEL.listRules().size
        for ((name, engine) in listOf("cel" to cel as Any, "rego" to rego as Any)) {
            val rules = when (engine) { is JvmCelEngine -> engine.listRules(); is JvmRegoEngine -> engine.listRules(); else -> error("") }
            val g = rules.find { it.id == "check_bucket_encryption" } ?: fail("$name: check_bucket_encryption must exist")
            assertEquals(Severity.ERROR, g.severity, "$name: severity")
            assertEquals(RuleOrigin.GUARD, g.origin, "$name: origin")
            assertEquals("S3 bucket must have encryption configured", g.description, "$name: description")
            assertEquals(baselineCount, rules.count { it.origin != RuleOrigin.GUARD }, "$name: must not pollute builtins")

            val report = when (engine) {
                is JvmCelEngine -> engine.validateStandard(templateBytes(badTemplate), defaultConfig(), badTemplate)
                is JvmRegoEngine -> engine.validateStandard(templateBytes(badTemplate), defaultConfig(), badTemplate)
                else -> error("")
            }
            val d = report.diagnostics.find { it.ruleId == "check_bucket_encryption" } ?: fail("$name: diagnostic must fire")
            assertEquals(Severity.ERROR, d.severity, "$name: diagnostic severity")
            assertEquals(RuleOrigin.GUARD, d.source, "$name: diagnostic source")
            assertEquals("Bucket", d.entity?.logicalId, "$name: entity logicalId")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "guard: listRules must be identical")
    }

    // ── Combined: 1 custom file + 1 guard file ──────────────────────────────

    @Test
    fun singleCombinedListRulesAndValidateMatchBetweenEngines() {
        val cel = JvmCelEngine(celCombinedConfig())
        val rego = JvmRegoEngine(regoCombinedConfig())

        // Rego discovers custom rule metadata during evaluation.
        rego.validateStandard(templateBytes("bad/invalid_deletion_policy.yaml"), defaultConfig(), "bad/invalid_deletion_policy.yaml")

        for ((name, rules) in listOf("cel" to cel.listRules(), "rego" to rego.listRules())) {
            assertEquals(RuleOrigin.CUSTOM, rules.find { it.id == "CUSTOM001" }?.origin, "$name: CUSTOM001 origin")
            assertEquals(RuleOrigin.GUARD, rules.find { it.id == "check_bucket_encryption" }?.origin, "$name: check_bucket_encryption origin")
            val ids = rules.map { it.id }
            assertEquals(ids, ids.sorted(), "$name: rules must be sorted")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "single_combined: listRules must be identical")
    }

    // ── Multi: 2 custom rules + 2 guard files (1 rule + 2 rules) ────────────

    private fun multiCombinedConfig(engine: String) = if (engine == "rego") EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "rego_multi_custom.rego", content = loadRule("rego_multi_custom.rego"))),
        guardRules = listOf(
            ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")),
            ExternalRuleSource(name = "guard_multi.guard", content = loadRule("guard_multi.guard")),
        )
    ) else EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "cel_multi_custom.json", content = loadRule("cel_multi_custom.json"))),
        guardRules = listOf(
            ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")),
            ExternalRuleSource(name = "guard_multi.guard", content = loadRule("guard_multi.guard")),
        )
    )

    @Test
    fun multiCombinedListRulesMatchBetweenEnginesWithExplicitValues() {
        val cel = JvmCelEngine(multiCombinedConfig("cel"))
        val rego = JvmRegoEngine(multiCombinedConfig("rego"))

        // Rego discovers custom rule metadata during evaluation.
        rego.validateStandard(templateBytes("bad/invalid_deletion_policy.yaml"), defaultConfig(), "bad/invalid_deletion_policy.yaml")

        for ((name, rules) in listOf("cel" to cel.listRules(), "rego" to rego.listRules())) {
            val c1 = rules.find { it.id == "CUSTOM010" } ?: fail("$name: CUSTOM010 must exist")
            assertEquals(Severity.ERROR, c1.severity, "$name: CUSTOM010 severity")
            assertEquals(RuleOrigin.CUSTOM, c1.origin, "$name: CUSTOM010 origin")
            assertEquals("S3 bucket must have versioning enabled", c1.description, "$name: CUSTOM010 description")

            val c2 = rules.find { it.id == "CUSTOM011" } ?: fail("$name: CUSTOM011 must exist")
            assertEquals(Severity.WARN, c2.severity, "$name: CUSTOM011 severity")
            assertEquals(RuleOrigin.CUSTOM, c2.origin, "$name: CUSTOM011 origin")
            assertEquals("S3 bucket should have lifecycle rules configured", c2.description, "$name: CUSTOM011 description")

            val enc = rules.find { it.id == "check_bucket_encryption" } ?: fail("$name: check_bucket_encryption must exist")
            assertEquals(RuleOrigin.GUARD, enc.origin, "$name: check_bucket_encryption origin")
            assertEquals("S3 bucket must have encryption configured", enc.description, "$name: check_bucket_encryption description")

            val ver = rules.find { it.id == "check_bucket_versioning" } ?: fail("$name: check_bucket_versioning must exist")
            assertEquals(RuleOrigin.GUARD, ver.origin, "$name: check_bucket_versioning origin")
            assertEquals("S3 bucket must have versioning enabled", ver.description, "$name: check_bucket_versioning description")

            val lc = rules.find { it.id == "check_bucket_lifecycle" } ?: fail("$name: check_bucket_lifecycle must exist")
            assertEquals(RuleOrigin.GUARD, lc.origin, "$name: check_bucket_lifecycle origin")
            assertEquals("S3 bucket should have lifecycle rules configured", lc.description, "$name: check_bucket_lifecycle description")

            val ids = rules.map { it.id }
            assertEquals(ids, ids.sorted(), "$name: rules must be sorted")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "multi_combined: listRules must be identical")
    }

    // ── Golden file validation ───────────────────────────────────────────────

    @TestFactory
    fun regoDetailedMatchesGolden(): List<DynamicTest> = goldenDetailedTests("rego", REGO)

    @TestFactory
    fun regoStandardMatchesGolden(): List<DynamicTest> = goldenStandardTests("rego", REGO)

    @TestFactory
    fun celDetailedMatchesGolden(): List<DynamicTest> = goldenDetailedTests("cel", CEL)

    @TestFactory
    fun celStandardMatchesGolden(): List<DynamicTest> = goldenStandardTests("cel", CEL)

    private fun goldenDetailedTests(engineName: String, engine: Any): List<DynamicTest> {
        return EXPECTED_TEMPLATES.map { rel ->
            DynamicTest.dynamicTest("$engineName detailed:$rel") {
                val actual = parseJson(gson.toJson(validateDetailed(engine, rel)))
                @Suppress("UNCHECKED_CAST")
                val expected = COMBINED_GOLDEN[rel] as Map<String, Any?>
                assertEquals(
                    stripGoldenExcludedFields(expected),
                    stripGoldenExcludedFields(actual, rel),
                    "$engineName detailed output for $rel differs from golden"
                )
            }
        }
    }

    private fun goldenStandardTests(engineName: String, engine: Any): List<DynamicTest> {
        return EXPECTED_TEMPLATES.map { rel ->
            DynamicTest.dynamicTest("$engineName standard:$rel") {
                val actual = parseJson(gson.toJson(validateStandard(engine, rel)))
                @Suppress("UNCHECKED_CAST")
                val expected = stripDetailedOnlyFields(COMBINED_GOLDEN[rel] as Map<String, Any?>)
                assertEquals(
                    stripGoldenExcludedFields(expected),
                    stripGoldenExcludedFields(actual, rel),
                    "$engineName standard output for $rel differs from golden"
                )
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun stripDetailedOnlyFields(report: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(report)
        val diags = (out["diagnostics"] as? List<Map<String, Any?>>) ?: return out
        out["diagnostics"] = diags.map { d ->
            val stripped = LinkedHashMap(d)
            for (field in FULL_ONLY_FIELDS) stripped.remove(field)
            stripped
        }
        return out
    }

    private fun validateDetailed(engine: Any, rel: String): DetailedReport =
        when (engine) {
            is CelEngine -> engine.validateDetailed(templateFile(rel), defaultConfig())
            is RegoEngine -> engine.validateDetailed(templateFile(rel), defaultConfig())
            else -> throw IllegalArgumentException("Unknown engine type: ${engine::class}")
        }

    private fun validateStandard(engine: Any, rel: String): StandardReport =
        when (engine) {
            is CelEngine -> engine.validateStandard(templateFile(rel), defaultConfig())
            is RegoEngine -> engine.validateStandard(templateFile(rel), defaultConfig())
            else -> throw IllegalArgumentException("Unknown engine type: ${engine::class}")
        }

    private fun parseJson(text: String): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        return JsonParser(text).parseValue() as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    private fun stripGoldenExcludedFields(report: Map<String, Any?>, filePath: String? = null): Map<String, Any?> {
        val out = LinkedHashMap(report)
        if (filePath != null) out["filePath"] = filePath
        out.remove("version")
        out.remove("performance")
        val metadata = out["metadata"] as? Map<String, Any?>
        if (metadata != null) {
            val trimmed = LinkedHashMap(metadata)
            trimmed.remove("rulesEvaluated")
            out["metadata"] = trimmed
        }
        return out
    }

    @Test
    fun performanceIsPresentWithTimingPerPhase() {
        val performance = REGO.validateDetailed(templateFile("good/generic.yaml"), defaultConfig()).performance
        val phases = listOf(
            performance.schemaInit,
            performance.engineInit,
            performance.modelBuild,
            performance.schemaValidate,
            performance.ruleEvaluation,
            performance.diagnosticFinalize,
            performance.validateTotal,
        )
        for (phase in phases) {
            assertTrue(phase.durationMs >= 0.0, "phase durationMs must be present and non-negative")
        }
    }

    companion object {
        private val resourcesRoot: File = listOf(
            File("${System.getProperty("user.dir")}/../../resources"),
            File("${System.getProperty("user.dir")}/../../../resources"),
        ).first { it.exists() }
        private val templatesRoot = File(resourcesRoot, "templates")
        private val expectedDir = File(resourcesRoot, "expected")
        private val rulesDir = File(resourcesRoot, "rules")

        private val gson = buildBindingsGson()

        private val EXPECTED_TEMPLATES: List<String>
        private val COMBINED_GOLDEN: Map<String, Any?>

        private val GOLDEN_DIRS = listOf("bad", "cdk", "good", "gh-issues", "integration", "issues", "lsp", "public", "quickstart")

        init {
            val goldenFile = File(expectedDir, "validation_reports.json")
            @Suppress("UNCHECKED_CAST")
            COMBINED_GOLDEN = JsonParser(goldenFile.readText()).parseValue() as Map<String, Any?>
            EXPECTED_TEMPLATES = discoverAllTemplates()
        }

        private fun discoverAllTemplates(): List<String> {
            val templates = mutableListOf<String>()
            for (sub in GOLDEN_DIRS) {
                val dir = File(templatesRoot, sub)
                if (dir.isDirectory) {
                    dir.walkTopDown().filter { it.isFile && it.extension in listOf("yaml", "yml", "json") }.forEach {
                        templates.add(it.relativeTo(templatesRoot).path.replace('\\', '/'))
                    }
                }
            }
            return templates.sorted()
        }

        private val FULL_ONLY_FIELDS = listOf("documentationUrl", "context", "ruleDescription", "phase", "section")

        private val CEL = CelEngine(EngineConfig())
        private val REGO = RegoEngine(EngineConfig())
    }
}

// ── Minimal JSON parser (for golden file comparison) ─────────────────────────

private class JsonParser(private val src: String) {
    private var pos = 0

    fun parseValue(): Any? {
        skipWhitespace()
        return when (peek()) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> parseString()
            't', 'f' -> parseBool()
            'n' -> parseNull()
            else -> parseNumber()
        }
    }

    private fun peek(): Char = src[pos]

    private fun skipWhitespace() {
        while (pos < src.length && src[pos].isWhitespace()) pos++
    }

    private fun expect(ch: Char) {
        skipWhitespace()
        require(src[pos] == ch) { "expected '$ch' at $pos, got '${src[pos]}'" }
        pos++
    }

    private fun parseObject(): Map<String, Any?> {
        expect('{')
        val out = linkedMapOf<String, Any?>()
        skipWhitespace()
        if (peek() == '}') { pos++; return out }
        while (true) {
            skipWhitespace()
            val key = parseString()
            expect(':')
            out[key] = parseValue()
            skipWhitespace()
            if (peek() == ',') { pos++; continue }
            expect('}')
            return out
        }
    }

    private fun parseArray(): List<Any?> {
        expect('[')
        val out = mutableListOf<Any?>()
        skipWhitespace()
        if (peek() == ']') { pos++; return out }
        while (true) {
            out.add(parseValue())
            skipWhitespace()
            if (peek() == ',') { pos++; continue }
            expect(']')
            return out
        }
    }

    private fun parseString(): String {
        expect('"')
        val sb = StringBuilder()
        while (pos < src.length) {
            val c = src[pos++]
            if (c == '"') return sb.toString()
            if (c == '\\' && pos < src.length) {
                sb.append(when (val esc = src[pos++]) {
                    'n' -> '\n'; 't' -> '\t'; 'r' -> '\r'; 'b' -> '\b'
                    'f' -> '\u000c'; '"' -> '"'; '\\' -> '\\'; '/' -> '/'
                    'u' -> {
                        val hex = src.substring(pos, pos + 4); pos += 4
                        hex.toInt(16).toChar()
                    }
                    else -> esc
                })
            } else {
                sb.append(c)
            }
        }
        throw IllegalStateException("unterminated string")
    }

    private fun parseBool(): Boolean {
        if (src.startsWith("true", pos)) { pos += 4; return true }
        if (src.startsWith("false", pos)) { pos += 5; return false }
        throw IllegalStateException("expected bool at $pos")
    }

    private fun parseNull(): Any? {
        require(src.startsWith("null", pos)) { "expected null at $pos" }
        pos += 4
        return null
    }

    private fun parseNumber(): Any {
        val start = pos
        if (peek() == '-') pos++
        while (pos < src.length && (src[pos].isDigit() || src[pos] in ".eE+-")) pos++
        val token = src.substring(start, pos)
        return if (token.contains('.') || token.contains('e') || token.contains('E'))
            token.toDouble() else token.toLong()
    }
}
