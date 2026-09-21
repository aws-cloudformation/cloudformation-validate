import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import software.amazon.cloudformation.validate.CompositeEngineConfigBuilder
import software.amazon.cloudformation.validate.EngineConfigBuilder
import software.amazon.cloudformation.validate.PseudoParameterOverridesBuilder
import software.amazon.cloudformation.validate.RuleFilterConfigBuilder
import software.amazon.cloudformation.validate.ValidateConfig
import software.amazon.cloudformation.validate.ValidateConfigBuilder
import software.amazon.cloudformation.validate.diagnostics.BudgetExhaustionRecord
import software.amazon.cloudformation.validate.diagnostics.DetailLevel
import software.amazon.cloudformation.validate.diagnostics.Diagnostic
import software.amazon.cloudformation.validate.engine.AwsCliValue
import software.amazon.cloudformation.validate.engine.CompositeEngineConfig
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.engine.ExternalRuleSource
import software.amazon.cloudformation.validate.idRange
import software.amazon.cloudformation.validate.limitAsLong
import software.amazon.cloudformation.validate.rules.IdRange
import software.amazon.cloudformation.validate.rules.ResourceIdFilter
import software.amazon.cloudformation.validate.rules.RuleFilterConfig
import software.amazon.cloudformation.validate.rules.Severity
import software.amazon.cloudformation.validate.schemavalidator.SchemaValidatorConfig
import software.amazon.cloudformation.validate.templatemodel.PseudoParameterOverrides
import software.amazon.cloudformation.validate.valueAsLong
import java.io.File
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.jar.JarFile

class JavaInteropContractTest {
    @Test
    fun everyMangledGetterInTheJarHasAJavaCallableLongView() {
        val mangledGetters = publicBindingClasses().flatMap { owner ->
            owner.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && MANGLED_GETTER.matches(it.name) }
                .map { owner to it }
        }
        assertTrue(mangledGetters.isNotEmpty(), "the scan must find the unsigned record getters")

        val missing = mangledGetters.filterNot { (owner, getter) ->
            val property = MANGLED_GETTER.matchEntire(getter.name)!!.groupValues[1].replaceFirstChar { it.lowercase() }
            javaInteropMethods.any { it.name == "${property}AsLong" && it.parameterTypes.firstOrNull() == owner }
        }
        assertEquals(
            emptyList<String>(),
            missing.map { (owner, getter) -> "${owner.name}.${getter.name}" },
            "unsigned fields without a JavaInterop <field>AsLong counterpart",
        )
    }

    @Test
    fun validateConfigBuilderMirrorsTheRecordFields() {
        assertEquals(propertyNames(ValidateConfig::class.java), setterNames(ValidateConfigBuilder::class.java))
    }

    @Test
    fun ruleFilterConfigBuilderMirrorsTheRecordFields() {
        assertEquals(propertyNames(RuleFilterConfig::class.java), setterNames(RuleFilterConfigBuilder::class.java))
    }

    @Test
    fun pseudoParameterOverridesBuilderMirrorsTheRecordFields() {
        assertEquals(
            propertyNames(PseudoParameterOverrides::class.java),
            setterNames(PseudoParameterOverridesBuilder::class.java),
        )
    }

    @Test
    fun engineConfigBuildersMirrorTheRecordFields() {
        assertEquals(propertyNames(EngineConfig::class.java), setterNames(EngineConfigBuilder::class.java))
        assertEquals(
            propertyNames(CompositeEngineConfig::class.java),
            setterNames(CompositeEngineConfigBuilder::class.java),
        )
    }

    @Test
    fun buildersProduceTheSameRecordsAsNamedArguments() {
        val exclude = RuleFilterConfig(ids = listOf("I9040"), resourceIds = listOf(ResourceIdFilter(resourceId = "DataBucket")))
        val overrides = PseudoParameterOverrides(region = "eu-west-1", stackName = "demo")
        val guard = ExternalRuleSource(name = "policy.guard", content = "rule always_true { true }")
        val schemas = SchemaValidatorConfig()

        assertEquals(
            ValidateConfig(exclude = exclude, detailLevel = DetailLevel.STANDARD, strict = true),
            ValidateConfigBuilder().exclude(exclude).detailLevel(DetailLevel.STANDARD).strict(true).build(),
        )
        assertEquals(
            exclude,
            RuleFilterConfigBuilder().ids(listOf("I9040")).resourceIds(listOf(ResourceIdFilter(resourceId = "DataBucket"))).build(),
        )
        assertEquals(overrides, PseudoParameterOverridesBuilder().region("eu-west-1").stackName("demo").build())
        assertEquals(
            EngineConfig(guardRules = listOf(guard), schemaValidatorConfig = schemas),
            EngineConfigBuilder().guardRules(listOf(guard)).schemaValidatorConfig(schemas).build(),
        )
        assertEquals(
            CompositeEngineConfig(regoRules = listOf(guard), guardRules = listOf(guard)),
            CompositeEngineConfigBuilder().regoRules(listOf(guard)).guardRules(listOf(guard)).build(),
        )
        assertEquals(ValidateConfig(), ValidateConfigBuilder().build())
    }

    @Test
    fun idRangeFactoryMatchesTheUnsignedConstructor() {
        assertEquals(IdRange(prefix = "W", start = 2000u, end = 2999u), idRange("W", 2000, 2999))
        assertEquals(IdRange(prefix = "E", start = 0u, end = UInt.MAX_VALUE), idRange("E", 0, UInt.MAX_VALUE.toLong()))
    }

    @Test
    fun unsignedLongViewsRejectValuesBeyondTheSignedRange() {
        val largestRepresentable = Long.MAX_VALUE.toULong()
        val representable = BudgetExhaustionRecord(kind = "k", description = "d.", limit = largestRepresentable, analysisIncomplete = false)
        val beyond = representable.copy(limit = largestRepresentable + 1u)

        assertEquals(Long.MAX_VALUE, representable.limitAsLong())
        assertEquals(Long.MAX_VALUE, AwsCliValue.UnsignedInteger(largestRepresentable).valueAsLong())
        val overflow = assertThrows(ArithmeticException::class.java) { beyond.limitAsLong() }
        assertTrue(overflow.message!!.contains("${largestRepresentable + 1u} exceeds Long.MAX_VALUE"), overflow.message)
        assertThrows(ArithmeticException::class.java) { AwsCliValue.UnsignedInteger(ULong.MAX_VALUE).valueAsLong() }
    }

    companion object {
        private const val BINDINGS_PACKAGE_PATH = "software/amazon/cloudformation/validate/"
        private val MANGLED_GETTER = Regex("^get([A-Z][A-Za-z0-9]*)-[A-Za-z0-9_-]+$")
        private val GENERATED_INTERNALS = listOf("FfiConverter", "Uniffi", "RustBuffer", "ForeignBytes")

        private val javaInteropMethods: List<Method> =
            Class.forName("software.amazon.cloudformation.validate.JavaInterop").declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && Modifier.isStatic(it.modifiers) }

        private fun publicBindingClasses(): List<Class<*>> {
            val jar = File(Diagnostic::class.java.protectionDomain.codeSource.location.toURI())
            return JarFile(jar).use { entries ->
                entries.entries().asSequence()
                    .map { it.name }
                    .filter { it.startsWith(BINDINGS_PACKAGE_PATH) && it.endsWith(".class") }
                    .filterNot { path -> GENERATED_INTERNALS.any { path.contains(it) } }
                    .map { Class.forName(it.removeSuffix(".class").replace('/', '.'), false, Diagnostic::class.java.classLoader) }
                    .filter { Modifier.isPublic(it.modifiers) }
                    .toList()
            }
        }

        private fun propertyNames(record: Class<*>): Set<String> =
            record.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && it.parameterCount == 0 && it.name.startsWith("get") }
                .map { it.name.removePrefix("get").replaceFirstChar { first -> first.lowercase() } }
                .toSet()

        private fun setterNames(builder: Class<*>): Set<String> =
            builder.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && it.name != "build" }
                .map { it.name }
                .toSet()
    }
}
