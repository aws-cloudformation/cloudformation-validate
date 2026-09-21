import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import software.amazon.cloudformation.validate.ApiKt;
import software.amazon.cloudformation.validate.CelEngine;
import software.amazon.cloudformation.validate.CompositeEngine;
import software.amazon.cloudformation.validate.CompositeEngineConfigBuilder;
import software.amazon.cloudformation.validate.Engine;
import software.amazon.cloudformation.validate.EngineConfigBuilder;
import software.amazon.cloudformation.validate.JavaInterop;
import software.amazon.cloudformation.validate.PseudoParameterOverridesBuilder;
import software.amazon.cloudformation.validate.RegoEngine;
import software.amazon.cloudformation.validate.RuleFilterConfigBuilder;
import software.amazon.cloudformation.validate.TemplateModel;
import software.amazon.cloudformation.validate.ValidateConfig;
import software.amazon.cloudformation.validate.ValidateConfigBuilder;
import software.amazon.cloudformation.validate.datasource.AdditionalSchemaSource;
import software.amazon.cloudformation.validate.diagnostics.Diagnostic;
import software.amazon.cloudformation.validate.diagnostics.ReportMetadata;
import software.amazon.cloudformation.validate.diagnostics.Summary;
import software.amazon.cloudformation.validate.diagnostics.ValidationReport;
import software.amazon.cloudformation.validate.engine.CompositeEngineConfig;
import software.amazon.cloudformation.validate.engine.EngineConfig;
import software.amazon.cloudformation.validate.engine.ExternalRuleSource;
import software.amazon.cloudformation.validate.gson.BindingsGson;
import software.amazon.cloudformation.validate.rules.IdRange;
import software.amazon.cloudformation.validate.rules.RuleFilterConfig;
import software.amazon.cloudformation.validate.rules.Severity;
import software.amazon.cloudformation.validate.templatemodel.ParameterInfo;
import software.amazon.cloudformation.validate.templatemodel.PseudoParameterOverrides;
import software.amazon.cloudformation.validate.templatemodel.SourceSpan;

class JavaConsumerTest {
    private static final String FIXTURE_TEMPLATE = String.join(
            "\n",
            "AWSTemplateFormatVersion: \"2010-09-09\"",
            "Parameters:",
            "  BucketSuffix:",
            "    Type: String",
            "    MinLength: 3",
            "    MaxLength: 10",
            "Resources:",
            "  DataBucket:",
            "    Type: AWS::S3::Bucket",
            "    Properties:",
            "      BucketName: !Sub \"example-bucket-${BucketSuffix}\"",
            "  WebSecurityGroup:",
            "    Type: AWS::EC2::SecurityGroup",
            "    Properties:",
            "      GroupDescription: Allow inbound web traffic",
            "      SecurityGroupIngress:",
            "        - IpProtocol: tcp",
            "          FromPort: 22",
            "          ToPort: 22",
            "          CidrIp: 0.0.0.0/0",
            "");
    private static final String OPEN_SSH_RULE_ID = "W2508";
    private static final long OPEN_SSH_START_LINE = 16;
    private static final long OPEN_SSH_START_COLUMN = 7;
    private static final long OPEN_SSH_END_COLUMN = 27;
    private static final long RESOURCES_SECTION_LINE = 7;
    private static final long BUCKET_SUFFIX_MIN_LENGTH = 3;
    private static final long BUCKET_SUFFIX_MAX_LENGTH = 10;
    private static final long UNSIGNED_32_MAX = 4294967295L;

    private static Engine rego;
    private static Engine cel;
    private static Engine composite;

    @BeforeAll
    static void constructEnginesWithoutArguments() {
        rego = new RegoEngine();
        cel = new CelEngine();
        composite = new CompositeEngine();
    }

    private static byte[] fixtureBytes() {
        return FIXTURE_TEMPLATE.getBytes(StandardCharsets.UTF_8);
    }

    private static File writeFixture(Path directory) throws IOException {
        Path template = directory.resolve("fixture.yaml");
        Files.write(template, fixtureBytes());
        return template.toFile();
    }

    private static List<String> ruleIds(ValidationReport report) {
        return report.getDiagnostics().stream().map(Diagnostic::getRuleId).collect(Collectors.toList());
    }

    private static Diagnostic openSshDiagnostic(ValidationReport report) {
        return report.getDiagnostics().stream()
                .filter(diagnostic -> OPEN_SSH_RULE_ID.equals(diagnostic.getRuleId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(OPEN_SSH_RULE_ID + " missing from " + ruleIds(report)));
    }

    @Test
    void shortFormOverloadsMatchTheFullyQualifiedCall(@TempDir Path directory) throws IOException {
        File template = writeFixture(directory);
        ValidationReport full = rego.validateTemplate(fixtureBytes(), new ValidateConfig(), template.getPath());

        assertEquals(full.getDiagnostics(), rego.validateTemplate(template).getDiagnostics());
        assertEquals(full.getDiagnostics(), rego.validateTemplate(fixtureBytes()).getDiagnostics());
        assertEquals(full.getDiagnostics(), rego.validateTemplate(fixtureBytes(), new ValidateConfig()).getDiagnostics());
        assertEquals(full.getDiagnostics(), rego.validateTemplate(FIXTURE_TEMPLATE).getDiagnostics());
        assertEquals(full.getDiagnostics(), rego.validateTemplate(FIXTURE_TEMPLATE, new ValidateConfig()).getDiagnostics());
        assertEquals(template.getPath(), full.getFilePath());
        assertEquals("template", rego.validateTemplate(fixtureBytes()).getFilePath());
        assertEquals("template", rego.validateTemplate(FIXTURE_TEMPLATE).getFilePath());
    }

    @Test
    void everyEngineReportsTheOpenSshPortFromTheStringOverload() {
        for (Engine engine : Arrays.asList(rego, cel, composite)) {
            ValidationReport report = engine.validateTemplate(FIXTURE_TEMPLATE);
            assertEquals("OK", report.getStatus().name(), engine.engineName());
            assertTrue(ruleIds(report).contains(OPEN_SSH_RULE_ID), engine.engineName() + ": " + ruleIds(report));
        }
    }

    @Test
    void diagnosticLocationsAreReadableAsLongs() {
        Diagnostic openSsh = openSshDiagnostic(rego.validateTemplate(FIXTURE_TEMPLATE));

        assertEquals(Long.valueOf(OPEN_SSH_START_LINE), JavaInterop.startLineAsLong(openSsh));
        assertEquals(Long.valueOf(OPEN_SSH_START_COLUMN), JavaInterop.startColumnAsLong(openSsh));
        assertEquals(Long.valueOf(OPEN_SSH_START_LINE), JavaInterop.endLineAsLong(openSsh));
        assertEquals(Long.valueOf(OPEN_SSH_END_COLUMN), JavaInterop.endColumnAsLong(openSsh));
    }

    @Test
    void summaryAndMetadataCountsAreReadableAsLongs() {
        ValidationReport report = rego.validateTemplate(FIXTURE_TEMPLATE);
        ReportMetadata metadata = report.getMetadata();
        Summary counts = metadata.getCounts();
        long warnings = report.getDiagnostics().stream().filter(d -> d.getSeverity() == Severity.WARN).count();
        long informational = report.getDiagnostics().stream().filter(d -> d.getSeverity() == Severity.INFO).count();

        assertEquals(warnings, JavaInterop.warningsAsLong(counts));
        assertEquals(informational, JavaInterop.informationalAsLong(counts));
        assertEquals(0L, JavaInterop.fatalAsLong(counts));
        assertEquals(0L, JavaInterop.errorsAsLong(counts));
        assertEquals(0L, JavaInterop.debugAsLong(counts));
        assertEquals(2L, JavaInterop.resourcesScannedAsLong(metadata));
        assertEquals(0L, JavaInterop.suppressedAsLong(metadata));
        assertTrue(JavaInterop.rulesEvaluatedAsLong(metadata) > 0, "rules evaluated");
    }

    @Test
    void excludingARuleIdThroughTheBuildersRemovesOnlyThatRule() {
        ValidationReport unfiltered = rego.validateTemplate(FIXTURE_TEMPLATE);
        RuleFilterConfig excludeOpenSsh = new RuleFilterConfigBuilder()
                .ids(Collections.singletonList(OPEN_SSH_RULE_ID))
                .build();

        ValidationReport filtered = rego.validateTemplate(
                FIXTURE_TEMPLATE, new ValidateConfigBuilder().exclude(excludeOpenSsh).build());

        List<String> expected = ruleIds(unfiltered).stream()
                .filter(ruleId -> !OPEN_SSH_RULE_ID.equals(ruleId))
                .collect(Collectors.toList());
        assertEquals(expected, ruleIds(filtered));
        assertEquals(0L, JavaInterop.warningsAsLong(filtered.getMetadata().getCounts()));
    }

    @Test
    void sourceSpansAndParameterConstraintsAreReadableAsLongs() {
        TemplateModel model = new TemplateModel(FIXTURE_TEMPLATE);
        SourceSpan resources = model.sourceLocation("Resources");
        ParameterInfo bucketSuffix = model.parameters().get("BucketSuffix");

        assertEquals(RESOURCES_SECTION_LINE, JavaInterop.startLineAsLong(resources));
        assertEquals(1L, JavaInterop.startColumnAsLong(resources));
        assertTrue(JavaInterop.endLineAsLong(resources) >= RESOURCES_SECTION_LINE, "end line");
        assertTrue(JavaInterop.endColumnAsLong(resources) >= 1L, "end column");
        assertEquals(Long.valueOf(BUCKET_SUFFIX_MIN_LENGTH), JavaInterop.minLengthAsLong(bucketSuffix));
        assertEquals(Long.valueOf(BUCKET_SUFFIX_MAX_LENGTH), JavaInterop.maxLengthAsLong(bucketSuffix));
    }

    @Test
    void idRangeFactoryBuildsARangeThatFiltersRules() {
        IdRange informationalRules = JavaInterop.idRange("I", 9000, 9999);
        assertEquals("I", informationalRules.getPrefix());
        assertEquals(9000L, JavaInterop.startAsLong(informationalRules));
        assertEquals(9999L, JavaInterop.endAsLong(informationalRules));

        ValidateConfig config = new ValidateConfigBuilder()
                .exclude(new RuleFilterConfigBuilder().idRanges(Collections.singletonList(informationalRules)).build())
                .build();
        ValidationReport report = rego.validateTemplate(FIXTURE_TEMPLATE, config);

        assertEquals(Collections.singletonList(OPEN_SSH_RULE_ID), ruleIds(report));
    }

    @Test
    void idRangeFactoryAcceptsTheFullUnsignedRangeAndRejectsBoundsOutsideIt() {
        IdRange widest = JavaInterop.idRange("E", 0, UNSIGNED_32_MAX);
        assertEquals(0L, JavaInterop.startAsLong(widest));
        assertEquals(UNSIGNED_32_MAX, JavaInterop.endAsLong(widest));

        IllegalArgumentException negative =
                assertThrows(IllegalArgumentException.class, () -> JavaInterop.idRange("E", -1, 10));
        assertTrue(negative.getMessage().contains("start"), negative.getMessage());
        IllegalArgumentException overflow =
                assertThrows(IllegalArgumentException.class, () -> JavaInterop.idRange("E", 0, UNSIGNED_32_MAX + 1));
        assertTrue(overflow.getMessage().contains("end"), overflow.getMessage());
    }

    @Test
    void validateConfigBuilderKeepsDefaultsForUnsetFields() {
        ValidateConfig config = new ValidateConfigBuilder().severityLevel(Severity.WARN).strict(true).build();
        ValidateConfig defaults = new ValidateConfig();

        assertEquals(Severity.WARN, config.getSeverityLevel());
        assertEquals(Boolean.TRUE, config.getStrict());
        assertEquals(defaults.getInclude(), config.getInclude());
        assertEquals(defaults.getExclude(), config.getExclude());
        assertEquals(defaults.getDetailLevel(), config.getDetailLevel());
        assertEquals(defaults.getParameterOverrides(), config.getParameterOverrides());
        assertEquals(defaults.getPseudoParameterOverrides(), config.getPseudoParameterOverrides());
        assertEquals(defaults.getDisableBuiltinRules(), config.getDisableBuiltinRules());
    }

    @Test
    void severityFloorAndStrictFromTheBuilderChangeTheReport() {
        ValidateConfig warnOnly = new ValidateConfigBuilder().severityLevel(Severity.WARN).build();
        ValidateConfig strictWarnOnly = new ValidateConfigBuilder().severityLevel(Severity.WARN).strict(true).build();

        ValidationReport warnReport = cel.validateTemplate(FIXTURE_TEMPLATE, warnOnly);
        ValidationReport strictReport = cel.validateTemplate(FIXTURE_TEMPLATE, strictWarnOnly);

        assertEquals(Collections.singletonList(OPEN_SSH_RULE_ID), ruleIds(warnReport));
        assertEquals(Severity.WARN, openSshDiagnostic(warnReport).getSeverity());
        assertEquals(Severity.ERROR, openSshDiagnostic(strictReport).getSeverity());
        assertTrue(strictReport.getMetadata().getStrict());
    }

    @Test
    void pseudoParameterOverridesBuilderSetsOnlyTheRequestedField() {
        PseudoParameterOverrides overrides = new PseudoParameterOverridesBuilder().region("eu-west-1").build();

        assertEquals("eu-west-1", overrides.getRegion());
        assertNull(overrides.getAccountId());
        assertNull(overrides.getPartition());
        assertEquals(new PseudoParameterOverrides().copy(null, null, null, "eu-west-1", null, null, null), overrides);
    }

    @Test
    void engineConfigBuildersProduceWorkingEngines(@TempDir Path directory) throws IOException {
        Path guardRule = directory.resolve("bucket_names.guard");
        Files.write(
                guardRule,
                "rule bucket_names_are_lowercase when %s3_buckets !empty {\n"
                        .concat("  %s3_buckets.Properties.BucketName == /^[a-z]/\n")
                        .concat("}\n")
                        .concat("let s3_buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n")
                        .getBytes(StandardCharsets.UTF_8));
        ExternalRuleSource guard = ApiKt.fileToExternalRuleSource(guardRule.toFile());

        EngineConfig engineConfig = new EngineConfigBuilder().guardRules(Collections.singletonList(guard)).build();
        CompositeEngineConfig compositeConfig =
                new CompositeEngineConfigBuilder().guardRules(Collections.singletonList(guard)).build();

        assertEquals(Collections.singletonList(guard), engineConfig.getGuardRules());
        assertEquals(new EngineConfig().getCustomRules(), engineConfig.getCustomRules());
        assertNull(engineConfig.getSchemaValidatorConfig());
        assertEquals(Collections.singletonList(guard), compositeConfig.getGuardRules());
        assertEquals("rego", new RegoEngine(engineConfig).engineName());
        assertEquals("composite", new CompositeEngine(compositeConfig).engineName());
    }

    @Test
    void helperFunctionsAcceptTheirOptionalParametersOmitted(@TempDir Path directory) throws IOException {
        Path schema = directory.resolve("schema.json");
        Files.write(schema, "{\"typeName\": \"AWS::Example::Thing\"}".getBytes(StandardCharsets.UTF_8));

        AdditionalSchemaSource withoutTypeName = ApiKt.fileToAdditionalSchemaSource(schema.toFile());
        AdditionalSchemaSource withTypeName = ApiKt.fileToAdditionalSchemaSource(schema.toFile(), "AWS::Example::Thing");
        Gson compact = BindingsGson.buildBindingsGson();
        Gson pretty = BindingsGson.buildBindingsGson(true);

        assertNull(withoutTypeName.getTypeName());
        assertEquals("AWS::Example::Thing", withTypeName.getTypeName());
        assertEquals(withoutTypeName.getSchema(), withTypeName.getSchema());
        assertEquals("{\"a\":1}", compact.toJson(Collections.singletonMap("a", 1)));
        assertEquals("{\n  \"a\": 1\n}", pretty.toJson(Collections.singletonMap("a", 1)));
    }
}
