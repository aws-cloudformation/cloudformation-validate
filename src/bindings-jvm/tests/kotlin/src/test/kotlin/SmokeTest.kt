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
    private fun detailedConfig() = ValidateConfig(severityLevel = Severity.DEBUG, detailLevel = DetailLevel.DETAILED)
    private fun standardConfig() = ValidateConfig(severityLevel = Severity.DEBUG, detailLevel = DetailLevel.STANDARD)

    private fun celCustomConfig() = EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "cel_custom.json", content = loadRule("cel_custom.json"))),
    )

    private fun regoCustomConfig() = EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "rego_custom.rego", content = loadRule("rego_custom.rego"))),
    )

    /** The composite counterpart of [celCustomConfig]: the same CEL custom rule, run by the built-in engine. */
    private fun compositeCelCustomConfig() = CompositeEngineConfig(
        celRules = listOf(ExternalRuleSource(name = "cel_custom.json", content = loadRule("cel_custom.json"))),
    )

    private fun guardConfig() = EngineConfig(
        guardRules = listOf(ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")))
    )

    private fun compositeGuardConfig() = CompositeEngineConfig(
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

    /** The composite counterpart of [celCombinedConfig]: the same CEL custom rule plus the same Guard rule. */
    private fun compositeCombinedConfig() = CompositeEngineConfig(
        celRules = listOf(ExternalRuleSource(name = "cel_custom.json", content = loadRule("cel_custom.json"))),
        guardRules = listOf(ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")))
    )

    // ── version ──────────────────────────────────────────────────────────────

    private fun readExpectedVersion(): String {
        val expectedVersionFile = File(expectedDir, "version.txt")
        val expectedVersion = expectedVersionFile.readText().trim()
        require(expectedVersion.isNotEmpty()) { "${expectedVersionFile.path} must not be empty" }
        return expectedVersion
    }

    @Test
    fun versionReturnsExpectedVersionFixture() {
        assertEquals(readExpectedVersion(), version())
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
    fun additionalSchemasApplyThroughThePublicConfigOnAllEngines() {
        val schemaValidatorConfig = SchemaValidatorConfig(
            additionalSchemas = listOf(AdditionalSchemaSource(typeName = null, schema = lambdaOverlaySchema)),
        )
        val config = EngineConfig(schemaValidatorConfig = schemaValidatorConfig)
        val compositeConfig = CompositeEngineConfig(schemaValidatorConfig = schemaValidatorConfig)
        val celBaseline = JvmCelEngine(EngineConfig()).validateTemplate(
            templateWithOverlayProperty,
            defaultConfig(),
            "overlay.yaml",
        )
        val regoBaseline = JvmRegoEngine(EngineConfig()).validateTemplate(
            templateWithOverlayProperty,
            defaultConfig(),
            "overlay.yaml",
        )
        val compositeBaseline = JvmCompositeEngine(CompositeEngineConfig()).validateTemplate(
            templateWithOverlayProperty,
            defaultConfig(),
            "overlay.yaml",
        )
        assertTrue(celBaseline.diagnostics.any { it.ruleId == "F3002" }, "CEL baseline must report the property")
        assertTrue(regoBaseline.diagnostics.any { it.ruleId == "F3002" }, "Rego baseline must report the property")
        assertTrue(compositeBaseline.diagnostics.any { it.ruleId == "F3002" }, "composite baseline must report the property")

        val cel = JvmCelEngine(config).validateTemplate(templateWithOverlayProperty, defaultConfig(), "overlay.yaml")
        val rego = JvmRegoEngine(config).validateTemplate(templateWithOverlayProperty, defaultConfig(), "overlay.yaml")
        val composite = JvmCompositeEngine(compositeConfig).validateTemplate(templateWithOverlayProperty, defaultConfig(), "overlay.yaml")
        assertFalse(cel.diagnostics.any { it.ruleId == "F3002" }, "CEL config must apply the overlay")
        assertFalse(rego.diagnostics.any { it.ruleId == "F3002" }, "Rego config must apply the overlay")
        assertFalse(composite.diagnostics.any { it.ruleId == "F3002" }, "composite config must apply the overlay")
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
    fun compositeListRulesSortedById() {
        val ids = COMPOSITE.listRules().map { it.id }
        assertTrue(ids.isNotEmpty(), "rule list must not be empty")
        assertEquals(ids, ids.sorted(), "rules must be sorted by id")
    }

    @Test
    fun allEnginesListIdenticalRules() {
        assertEquals(
            gson.toJson(CEL.listRules()),
            gson.toJson(REGO.listRules()),
            "CEL and Rego must list identical rules"
        )
        assertEquals(
            gson.toJson(CEL.listRules()),
            gson.toJson(COMPOSITE.listRules()),
            "CEL and composite must list identical rules"
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
        val report = CEL.validateTemplate(templateFile("empty.yaml"), defaultConfig())
        assertEquals("ERROR", report.status.name)
        assertEquals("F1101", report.diagnostics[0].ruleId)
        assertEquals(Severity.FATAL, report.diagnostics[0].severity)
    }

    @Test
    fun regoReturnsF1101ForEmptyTemplate() {
        val report = REGO.validateTemplate(templateFile("empty.yaml"), defaultConfig())
        assertEquals("ERROR", report.status.name)
        assertEquals("F1101", report.diagnostics[0].ruleId)
        assertEquals(Severity.FATAL, report.diagnostics[0].severity)
    }

    @Test
    fun compositeReturnsF1101ForEmptyTemplate() {
        val report = COMPOSITE.validateTemplate(templateFile("empty.yaml"), defaultConfig())
        assertEquals("ERROR", report.status.name)
        assertEquals("F1101", report.diagnostics[0].ruleId)
        assertEquals(Severity.FATAL, report.diagnostics[0].severity)
    }

    // ── Good templates ─────────────────────────────────────────────────────

    @Test
    fun goodTemplatePassesAllEngines() {
        for ((name, engine) in listOf("cel" to CEL, "rego" to REGO, "composite" to COMPOSITE)) {
            val report = engine.validateTemplate(templateFile("good/aurora_dbinstance.yaml"), defaultConfig())
            assertEquals("OK", report.status.name, "$name: good template status")
            val errors = report.diagnostics.filter { it.severity == Severity.ERROR || it.severity == Severity.FATAL }
            assertTrue(errors.isEmpty(), "$name: good template must have no errors, got $errors")
        }
    }

    // ── Custom rules: 1 file, 1 rule ──────────────────────────────────────

    @Test
    fun customRuleListRulesAndValidateMatchBetweenEngines() {
        val cel = JvmCelEngine(celCustomConfig())
        val rego = JvmRegoEngine(regoCustomConfig())
        val composite = JvmCompositeEngine(compositeCelCustomConfig())
        val badTemplate = "bad/invalid_deletion_policy.yaml"
        val engines = listOf("cel" to cel as Any, "rego" to rego as Any, "composite" to composite as Any)

        for ((name, engine) in engines) {
            val report = when (engine) {
                is JvmCelEngine -> engine.validateTemplate(templateBytes(badTemplate), defaultConfig(), badTemplate)
                is JvmRegoEngine -> engine.validateTemplate(templateBytes(badTemplate), defaultConfig(), badTemplate)
                is JvmCompositeEngine -> engine.validateTemplate(templateBytes(badTemplate), defaultConfig(), badTemplate)
                else -> error("")
            }
            val d = report.diagnostics.find { it.ruleId == "CUSTOM001" } ?: fail("$name: CUSTOM001 diagnostic must fire")
            assertEquals(Severity.ERROR, d.severity, "$name: diagnostic severity")
            assertEquals("Bucket", d.entity?.logicalId, "$name: entity logicalId")
            assertEquals("AWS::S3::Bucket", d.entity?.resourceType, "$name: entity resourceType")
        }

        val baselineCount = CEL.listRules().size
        for ((name, engine) in engines) {
            val rules = when (engine) { is JvmCelEngine -> engine.listRules(); is JvmRegoEngine -> engine.listRules(); is JvmCompositeEngine -> engine.listRules(); else -> error("") }
            val c = rules.find { it.id == "CUSTOM001" } ?: fail("$name: CUSTOM001 must exist")
            assertEquals(Severity.ERROR, c.severity, "$name: CUSTOM001 severity")
            assertEquals(RuleOrigin.CUSTOM, c.origin, "$name: CUSTOM001 origin")
            assertEquals("S3 bucket must have encryption configured", c.description, "$name: CUSTOM001 description")
            assertEquals(baselineCount, rules.count { it.origin != RuleOrigin.CUSTOM }, "$name: must not pollute builtins")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "custom: listRules must be identical")
        assertEquals(gson.toJson(cel.listRules()), gson.toJson(composite.listRules()), "custom: composite listRules must be identical")
    }

    // ── Guard rules: 1 file, 1 rule ─────────────────────────────────────────

    @Test
    fun guardRuleListRulesAndValidateMatchBetweenEngines() {
        val cel = JvmCelEngine(guardConfig())
        val rego = JvmRegoEngine(guardConfig())
        val composite = JvmCompositeEngine(compositeGuardConfig())
        val badTemplate = "bad/invalid_deletion_policy.yaml"

        val baselineCount = CEL.listRules().size
        for ((name, engine) in listOf("cel" to cel as Any, "rego" to rego as Any, "composite" to composite as Any)) {
            val rules = when (engine) { is JvmCelEngine -> engine.listRules(); is JvmRegoEngine -> engine.listRules(); is JvmCompositeEngine -> engine.listRules(); else -> error("") }
            val g = rules.find { it.id == "check_bucket_encryption" } ?: fail("$name: check_bucket_encryption must exist")
            assertEquals(Severity.ERROR, g.severity, "$name: severity")
            assertEquals(RuleOrigin.GUARD, g.origin, "$name: origin")
            assertEquals("S3 bucket must have encryption configured", g.description, "$name: description")
            assertEquals(baselineCount, rules.count { it.origin != RuleOrigin.GUARD }, "$name: must not pollute builtins")

            val report = when (engine) {
                is JvmCelEngine -> engine.validateTemplate(templateBytes(badTemplate), defaultConfig(), badTemplate)
                is JvmRegoEngine -> engine.validateTemplate(templateBytes(badTemplate), defaultConfig(), badTemplate)
                is JvmCompositeEngine -> engine.validateTemplate(templateBytes(badTemplate), defaultConfig(), badTemplate)
                else -> error("")
            }
            val d = report.diagnostics.find { it.ruleId == "check_bucket_encryption" } ?: fail("$name: diagnostic must fire")
            assertEquals(Severity.ERROR, d.severity, "$name: diagnostic severity")
            assertEquals(RuleOrigin.GUARD, d.source, "$name: diagnostic source")
            assertEquals("Bucket", d.entity?.logicalId, "$name: entity logicalId")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "guard: listRules must be identical")
        assertEquals(gson.toJson(cel.listRules()), gson.toJson(composite.listRules()), "guard: composite listRules must be identical")
    }

    // ── Combined: 1 custom file + 1 guard file ──────────────────────────────

    @Test
    fun singleCombinedListRulesAndValidateMatchBetweenEngines() {
        val cel = JvmCelEngine(celCombinedConfig())
        val rego = JvmRegoEngine(regoCombinedConfig())
        val composite = JvmCompositeEngine(compositeCombinedConfig())

        // Rego discovers custom rule metadata during evaluation.
        rego.validateTemplate(templateBytes("bad/invalid_deletion_policy.yaml"), defaultConfig(), "bad/invalid_deletion_policy.yaml")

        for ((name, rules) in listOf("cel" to cel.listRules(), "rego" to rego.listRules(), "composite" to composite.listRules())) {
            assertEquals(RuleOrigin.CUSTOM, rules.find { it.id == "CUSTOM001" }?.origin, "$name: CUSTOM001 origin")
            assertEquals(RuleOrigin.GUARD, rules.find { it.id == "check_bucket_encryption" }?.origin, "$name: check_bucket_encryption origin")
            val ids = rules.map { it.id }
            assertEquals(ids, ids.sorted(), "$name: rules must be sorted")
        }

        assertEquals(gson.toJson(cel.listRules()), gson.toJson(rego.listRules()), "single_combined: listRules must be identical")
        assertEquals(gson.toJson(cel.listRules()), gson.toJson(composite.listRules()), "single_combined: composite listRules must be identical")
    }

    // ── Multi: 2 custom rules + 2 guard files (1 rule + 2 rules) ────────────

    private fun multiGuardRules() = listOf(
        ExternalRuleSource(name = "guard_encryption.guard", content = loadRule("guard_encryption.guard")),
        ExternalRuleSource(name = "guard_multi.guard", content = loadRule("guard_multi.guard")),
    )

    private fun multiCombinedConfig(engine: String) = if (engine == "rego") EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "rego_multi_custom.rego", content = loadRule("rego_multi_custom.rego"))),
        guardRules = multiGuardRules(),
    ) else EngineConfig(
        customRules = listOf(ExternalRuleSource(name = "cel_multi_custom.json", content = loadRule("cel_multi_custom.json"))),
        guardRules = multiGuardRules(),
    )

    /** The composite counterpart of the multi-combined configs: the CEL custom rules plus both Guard files. */
    private fun compositeMultiCombinedConfig() = CompositeEngineConfig(
        celRules = listOf(ExternalRuleSource(name = "cel_multi_custom.json", content = loadRule("cel_multi_custom.json"))),
        guardRules = multiGuardRules(),
    )

    @Test
    fun multiCombinedListRulesMatchBetweenEnginesWithExplicitValues() {
        val cel = JvmCelEngine(multiCombinedConfig("cel"))
        val rego = JvmRegoEngine(multiCombinedConfig("rego"))
        val composite = JvmCompositeEngine(compositeMultiCombinedConfig())

        // Rego discovers custom rule metadata during evaluation.
        rego.validateTemplate(templateBytes("bad/invalid_deletion_policy.yaml"), defaultConfig(), "bad/invalid_deletion_policy.yaml")

        for ((name, rules) in listOf("cel" to cel.listRules(), "rego" to rego.listRules(), "composite" to composite.listRules())) {
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
        assertEquals(gson.toJson(cel.listRules()), gson.toJson(composite.listRules()), "multi_combined: composite listRules must be identical")
    }

    // ── CompositeEngine ──────────────────────────────────────────────────────

    private fun compositeCustomConfig() = CompositeEngineConfig(
        regoRules = listOf(ExternalRuleSource(name = "rego_custom.rego", content = loadRule("rego_custom.rego"))),
    )

    @Test
    fun compositeReportsNameComposite() {
        assertEquals("composite", JvmCompositeEngine(CompositeEngineConfig()).engineName())
    }

    @Test
    fun compositeDefaultDiagnosticsAndRulesMatchStandaloneEngines() {
        val composite = CompositeEngine()
        val template = templateFile("bad/invalid_deletion_policy.yaml")

        val celDiagnostics = CEL.validateTemplate(template, defaultConfig()).diagnostics
        val regoDiagnostics = REGO.validateTemplate(template, defaultConfig()).diagnostics
        val compositeDiagnostics = composite.validateTemplate(template, defaultConfig()).diagnostics

        assertTrue(celDiagnostics.isNotEmpty(), "template must produce built-in diagnostics")
        assertEquals(gson.toJson(celDiagnostics), gson.toJson(compositeDiagnostics), "composite must match CEL diagnostics")
        assertEquals(gson.toJson(regoDiagnostics), gson.toJson(compositeDiagnostics), "composite must match Rego diagnostics")
        assertEquals(gson.toJson(CEL.listRules()), gson.toJson(composite.listRules()), "composite listRules must match the standalone engines")
    }

    @Test
    fun compositeCustomRegoRuleFiresAndPreservesBuiltins() {
        val badTemplate = "bad/invalid_deletion_policy.yaml"
        val composite = CompositeEngine(compositeCustomConfig())
        val report = composite.validateTemplate(templateFile(badTemplate), defaultConfig())

        val custom = report.diagnostics.filter { it.ruleId == "CUSTOM001" }
        assertEquals(1, custom.size, "the custom Rego rule must fire exactly once")
        assertEquals(Severity.ERROR, custom[0].severity, "CUSTOM001 severity")
        assertEquals(RuleOrigin.CUSTOM, custom[0].source, "CUSTOM001 source")
        assertEquals("Bucket", custom[0].entity?.logicalId, "CUSTOM001 entity logicalId")
        assertEquals("AWS::S3::Bucket", custom[0].entity?.resourceType, "CUSTOM001 entity resourceType")

        val builtinDiagnostics = report.diagnostics.filter { it.source != RuleOrigin.CUSTOM }
        val standaloneBuiltins = CEL.validateTemplate(templateFile(badTemplate), defaultConfig()).diagnostics
        assertEquals(
            gson.toJson(standaloneBuiltins),
            gson.toJson(builtinDiagnostics),
            "built-in diagnostics must be preserved exactly, matching a standalone built-in run"
        )

        val listed = composite.listRules().find { it.id == "CUSTOM001" } ?: fail("CUSTOM001 must be listed")
        assertEquals(RuleOrigin.CUSTOM, listed.origin, "CUSTOM001 origin")
        assertEquals("S3 bucket must have encryption configured", listed.description, "CUSTOM001 description")
    }

    @TestFactory
    fun regoDetailedMatchesSnapshot(): List<DynamicTest> = snapshotDetailedTests("rego", REGO)

    @TestFactory
    fun regoStandardMatchesSnapshot(): List<DynamicTest> = snapshotStandardTests("rego", REGO)

    @TestFactory
    fun celDetailedMatchesSnapshot(): List<DynamicTest> = snapshotDetailedTests("cel", CEL)

    @TestFactory
    fun celStandardMatchesSnapshot(): List<DynamicTest> = snapshotStandardTests("cel", CEL)

    @TestFactory
    fun compositeDetailedMatchesSnapshot(): List<DynamicTest> = snapshotDetailedTests("composite", COMPOSITE)

    @TestFactory
    fun compositeStandardMatchesSnapshot(): List<DynamicTest> = snapshotStandardTests("composite", COMPOSITE)

    @Test
    fun omittingDetailLevelDefaultsToDetailed() {
        val template = templateFile("good/generic.yaml")
        val default = REGO.validateTemplate(template, ValidateConfig(severityLevel = Severity.DEBUG))
        val explicitDetailed = REGO.validateTemplate(template, detailedConfig())
        val explicitStandard = REGO.validateTemplate(template, standardConfig())

        assertTrue(
            default.diagnostics.any { it.ruleDescription != null },
            "the default report must carry enrichment fields",
        )
        assertTrue(
            explicitStandard.diagnostics.all { it.ruleDescription == null },
            "the STANDARD detail level must leave enrichment fields absent",
        )
        assertEquals(
            stripSnapshotExcludedFields(parseJson(gson.toJson(explicitDetailed))),
            stripSnapshotExcludedFields(parseJson(gson.toJson(default))),
            "omitting detailLevel must produce the same report as an explicit DETAILED detail level",
        )
    }

    private fun snapshotDetailedTests(engineName: String, engine: Any): List<DynamicTest> {
        return EXPECTED_TEMPLATES.map { rel ->
            DynamicTest.dynamicTest("$engineName detailed:$rel") {
                val actual = parseJson(gson.toJson(validateWithDetailLevel(engine, rel, detailedConfig())))
                @Suppress("UNCHECKED_CAST")
                val expected = COMBINED_SNAPSHOTS[rel] as Map<String, Any?>
                assertEquals(
                    stripSnapshotExcludedFields(expected),
                    stripSnapshotExcludedFields(actual, rel),
                    "$engineName detailed output for $rel differs from snapshot"
                )
            }
        }
    }

    private fun snapshotStandardTests(engineName: String, engine: Any): List<DynamicTest> {
        return EXPECTED_TEMPLATES.map { rel ->
            DynamicTest.dynamicTest("$engineName standard:$rel") {
                val actual = parseJson(gson.toJson(validateWithDetailLevel(engine, rel, standardConfig())))
                @Suppress("UNCHECKED_CAST")
                val expected = stripEnrichmentFields(COMBINED_SNAPSHOTS[rel] as Map<String, Any?>)
                assertEquals(
                    stripSnapshotExcludedFields(expected),
                    stripSnapshotExcludedFields(actual, rel),
                    "$engineName standard output for $rel differs from snapshot"
                )
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun stripEnrichmentFields(report: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(report)
        val diags = (out["diagnostics"] as? List<Map<String, Any?>>) ?: return out
        out["diagnostics"] = diags.map { d ->
            val stripped = LinkedHashMap(d)
            for (field in ENRICHMENT_FIELDS) stripped.remove(field)
            stripped
        }
        return out
    }

    private fun validateWithDetailLevel(engine: Any, rel: String, config: ValidateConfig): ValidationReport =
        when (engine) {
            is CelEngine -> engine.validateTemplate(templateFile(rel), config)
            is RegoEngine -> engine.validateTemplate(templateFile(rel), config)
            is CompositeEngine -> engine.validateTemplate(templateFile(rel), config)
            else -> throw IllegalArgumentException("Unknown engine type: ${engine::class}")
        }

    private fun parseJson(text: String): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        return JsonParser(text).parseValue() as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    private fun stripSnapshotExcludedFields(report: Map<String, Any?>, filePath: String? = null): Map<String, Any?> {
        val out = LinkedHashMap(report)
        if (filePath != null) out["filePath"] = filePath
        out.remove("version")
        out.remove("performance")
        val metadata = out["metadata"] as? Map<String, Any?>
        if (metadata != null) {
            val trimmed = LinkedHashMap(metadata)
            trimmed.remove("rulesEvaluated")
            trimmed.remove("cfnLintVersion")
            trimmed.remove("resourceSchemaVersion")
            trimmed.remove("suppressed")
            out["metadata"] = trimmed
        }
        return out
    }

    @Test
    fun performanceIsPresentWithTimingPerPhase() {
        val performance = REGO.validateTemplate(templateFile("good/generic.yaml"), defaultConfig()).performance
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

    // ── AWS CLI command validation ────────────────────────────────────────────

    private val awsCliEngines: List<Pair<String, Engine>> = listOf("rego" to REGO, "cel" to CEL, "composite" to COMPOSITE)

    private fun diagnosticKeys(report: ValidationReport): List<String> =
        report.diagnostics.map { "${it.ruleId}|${it.severity}|${it.startLine}|${it.startColumn}" }.sorted()

    @Suppress("UNCHECKED_CAST")
    private fun synthesizedBucketName(template: ByteArray?): String {
        assertNotNull(template, "a validated request must carry the synthesized template bytes")
        val document = JsonParser(String(template!!)).parseValue() as Map<String, Any?>
        val resource = (document["Resources"] as Map<String, Any?>)["Resource"] as Map<String, Any?>
        assertEquals("AWS::S3::Bucket", resource["Type"], "synthesized resource type")
        return (resource["Properties"] as Map<String, Any?>)["BucketName"] as String
    }

    @Test
    fun awsCliS3CreateBucketSynthesizesOnAllEngines() {
        val request = AwsCliCommand("s3", "CreateBucket", mapOf("Bucket" to "synthetic-bucket"))
        val perEngine = LinkedHashMap<String, AwsCliCommandValidation>()
        for ((name, engine) in awsCliEngines) {
            val validation = engine.validateAwsCliCommand(request)
            assertEquals(AwsCliCommandValidationStatus.VALIDATED, validation.status, "$name: status")
            assertEquals(AwsCliOperationKind.CLOUD_FORMATION_CREATE, validation.operationKind, "$name: operation kind")
            assertEquals(listOf("AWS::S3::Bucket"), validation.resourceTypes, "$name: resource types")
            assertEquals(AwsCliTemplateSource.SYNTHESIZED_CREATE, validation.templateSource, "$name: template source")
            assertNotNull(validation.report, "$name: report must be present for a validated request")
            assertEquals("synthetic-bucket", synthesizedBucketName(validation.template), "$name: synthesized bucket name")
            perEngine[name] = validation
        }
        // Rego/CEL parity on the modeled template and diagnostics, not timings.
        assertTrue(
            perEngine.getValue("rego").template.contentEquals(perEngine.getValue("cel").template),
            "engines must synthesize identical templates",
        )
        val rego = perEngine.getValue("rego")
        for ((name, other) in perEngine) {
            if (name == "rego") continue
            assertArrayEquals(rego.template, other.template, "$name must synthesize the same template as rego")
            assertEquals(
                diagnosticKeys(rego.report!!),
                diagnosticKeys(other.report!!),
                "$name must agree with rego on diagnostics",
            )
        }
    }

    @Test
    fun awsCliValidateTemplatePreservesExactBytes() {
        // Distinctive whitespace and key order a reserialization would not reproduce.
        val templateBody = "{\n    \"Resources\": {\n        \"Bucket\": { \"Type\": \"AWS::S3::Bucket\" }\n    }\n}".toByteArray()
        val request = AwsCliCommand("cloudformation", "ValidateTemplate", mapOf("TemplateBody" to templateBody))
        for ((name, engine) in awsCliEngines) {
            val validation = engine.validateAwsCliCommand(request)
            assertEquals(AwsCliCommandValidationStatus.VALIDATED, validation.status, "$name: status")
            assertEquals(AwsCliTemplateSource.TEMPLATE_BODY, validation.templateSource, "$name: template source")
            assertTrue(
                templateBody.contentEquals(validation.template),
                "$name: TemplateBody must be preserved byte-for-byte",
            )
        }
    }

    @Test
    fun awsCliConservativelySkipsNestedDynamoDbFields() {
        val request = AwsCliCommand(
            "dynamodb",
            "CreateTable",
            mapOf(
                "TableName" to "Synthetic",
                "KeySchema" to listOf(mapOf("AttributeName" to "id", "KeyType" to "HASH")),
                "AttributeDefinitions" to listOf(mapOf("AttributeName" to "id", "AttributeType" to "S")),
                "BillingMode" to "PAY_PER_REQUEST",
            ),
        )
        for ((name, engine) in awsCliEngines) {
            val validation = engine.validateAwsCliCommand(request)
            assertEquals(AwsCliCommandValidationStatus.SKIPPED, validation.status, "$name: status")
            assertNull(validation.report, "$name: a skipped request must have no report")
            assertNull(validation.template, "$name: a skipped request must have no template")
            assertEquals(listOf("AWS::DynamoDB::Table"), validation.resourceTypes, "$name: resource type still identified")
            assertTrue(
                validation.reason.contains("has no mapping"),
                "$name: reason must explain the unmapped nested field: ${validation.reason}",
            )
        }
    }

    @Test
    fun awsCliDoesNotGuessNoncanonicalServiceAlias() {
        // CloudWatch's canonical botocore name is "cloudwatch"; "monitoring" is its
        // signing name. The core resolves the canonical name but never the alias.
        val canonical = AwsCliCommand("cloudwatch", "PutMetricAlarm", mapOf("AlarmName" to "synthetic"))
        val alias = AwsCliCommand("monitoring", "PutMetricAlarm", mapOf("AlarmName" to "synthetic"))
        for ((name, engine) in awsCliEngines) {
            val canonicalValidation = engine.validateAwsCliCommand(canonical)
            assertTrue(
                canonicalValidation.resourceTypes.contains("AWS::CloudWatch::Alarm"),
                "$name: canonical cloudwatch:PutMetricAlarm must identify AWS::CloudWatch::Alarm",
            )
            val aliasValidation = engine.validateAwsCliCommand(alias)
            assertEquals(AwsCliCommandValidationStatus.SKIPPED, aliasValidation.status, "$name: alias status")
            assertFalse(
                aliasValidation.resourceTypes.contains("AWS::CloudWatch::Alarm"),
                "$name: signing alias 'monitoring' must not resolve to AWS::CloudWatch::Alarm",
            )
            assertNull(aliasValidation.template, "$name: an unresolved alias must not synthesize a template")
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
        private val COMBINED_SNAPSHOTS: Map<String, Any?>

        private const val CHUNK_PREFIX = "validation_reports"
        private const val CHUNK_EXTENSION = ".json"

        init {
            COMBINED_SNAPSHOTS = loadCombinedSnapshots()
            EXPECTED_TEMPLATES = discoverAllTemplates()
        }

        /**
         * Discover all numbered snapshot chunk files in numeric order and merge
         * them strictly. Fails on no chunks, non-object JSON, or duplicate keys.
         */
        private fun loadCombinedSnapshots(): Map<String, Any?> {
            val pattern = Regex("^${Regex.escape(CHUNK_PREFIX)}([1-9][0-9]*)${Regex.escape(CHUNK_EXTENSION)}$")
            val chunkFiles = (expectedDir.listFiles() ?: error("cannot list $expectedDir"))
                .filter { it.isFile }
                .mapNotNull { file ->
                    pattern.matchEntire(file.name)?.let { match ->
                        val indexStr = match.groupValues[1]
                        val index = indexStr.toIntOrNull()
                            ?: error("snapshot chunk index overflows Int: ${file.name}")
                        require(index >= 1) { "snapshot chunk index must be >= 1: ${file.name}" }
                        index to file
                    }
                }
                .sortedBy { it.first }

            require(chunkFiles.isNotEmpty()) {
                "no snapshot chunk files (${CHUNK_PREFIX}N${CHUNK_EXTENSION}) found in $expectedDir"
            }

            for ((i, pair) in chunkFiles.withIndex()) {
                require(pair.first == i + 1) {
                    "non-contiguous snapshot chunk sequence: expected index ${i + 1} but found ${pair.first}"
                }
            }

            val merged = linkedMapOf<String, Any?>()
            for ((_, file) in chunkFiles) {
                @Suppress("UNCHECKED_CAST")
                val chunkData = JsonParser(file.readText()).parseValue() as? Map<String, Any?>
                    ?: error("snapshot chunk ${file.name} is not a JSON object")
                for ((key, value) in chunkData) {
                    require(key !in merged) {
                        "duplicate template key \"$key\" in chunk ${file.name}"
                    }
                    merged[key] = value
                }
            }
            return merged
        }

        /**
         * Recursively scan the entire templates directory for .yaml/.yml/.json.
         */
        private fun discoverAllTemplates(): List<String> {
            require(templatesRoot.isDirectory) {
                "templates directory does not exist: ${templatesRoot.absolutePath}"
            }
            val templates = mutableListOf<String>()
            templatesRoot.walkTopDown().filter { it.isFile && it.extension in listOf("yaml", "yml", "json") }.forEach {
                templates.add(it.relativeTo(templatesRoot).path.replace('\\', '/'))
            }
            require(templates.isNotEmpty()) {
                "no templates discovered in ${templatesRoot.absolutePath}"
            }
            return templates.sorted()
        }

        private val ENRICHMENT_FIELDS = listOf("documentationUrl", "context", "ruleDescription", "phase", "section")

        private val CEL = CelEngine(EngineConfig())
        private val REGO = RegoEngine(EngineConfig())
        private val COMPOSITE = CompositeEngine()
    }
}

// ── Minimal JSON parser (for snapshot file comparison) ─────────────────────────

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
