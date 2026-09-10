package software.amazon.cloudformation.validate

import software.amazon.cloudformation.validate.datasource.AdditionalSchemaSource
import software.amazon.cloudformation.validate.diagnostics.Diagnostic
import software.amazon.cloudformation.validate.diagnostics.ValidationReport
import software.amazon.cloudformation.validate.engine.AwsCliCommandContext as NativeAwsCliCommand
import software.amazon.cloudformation.validate.engine.AwsCliCommandValidation
import software.amazon.cloudformation.validate.engine.AwsCliValue as NativeAwsCliValue
import software.amazon.cloudformation.validate.engine.CompositeEngineConfig
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.engine.ExternalRuleSource
import software.amazon.cloudformation.validate.rules.RuleInfo
import software.amazon.cloudformation.validate.schemavalidator.SchemaValidatorConfig
import java.io.File

interface Engine {
    fun validateTemplate(template: File, config: ValidateConfig = ValidateConfig()): ValidationReport
    fun validateAwsCliCommand(
        request: AwsCliCommand,
        config: ValidateConfig = ValidateConfig(),
    ): AwsCliCommandValidation
    fun listRules(): List<RuleInfo>
    fun engineName(): String
}

/**
 * Service, operation, and request values for CloudFormation validation.
 *
 * [serviceName] is the canonical botocore service name (for example "s3" or
 * "cloudformation") and is the authoritative mapping identity, normalized only
 * for ASCII case - never a signing name, ARN prefix, or endpoint alias. A future
 * AWS SDK adapter, in any language, must translate its native service identity to
 * the canonical botocore [serviceName] before calling; the core does not guess
 * aliases.
 *
 * [parameters] accepts nested maps/lists, strings, numbers, booleans, nulls,
 * byte arrays, and Java time values. Unsupported values are marked explicitly
 * and conservatively omitted during request-to-template synthesis.
 */
class AwsCliCommand @JvmOverloads constructor(
    val serviceName: String,
    val operationName: String,
    parameters: Map<String, Any?>,
    val servicePrefix: String? = null,
    val httpMethod: String? = null,
    val isReadOnly: Boolean? = null,
) {
    val parameters: Map<String, Any?> = LinkedHashMap(parameters)

    internal fun toNative(): NativeAwsCliCommand =
        NativeAwsCliCommand(
            serviceName = serviceName,
            operationName = operationName,
            parameters = parameters.mapValues { (_, value) -> value.toNativeAwsCliValue() },
            servicePrefix = servicePrefix,
            httpMethod = httpMethod,
            isReadOnly = isReadOnly,
        )
}

private fun Any?.toNativeAwsCliValue(): NativeAwsCliValue =
    when (this) {
        null -> NativeAwsCliValue.Null
        is Boolean -> NativeAwsCliValue.Boolean(value = this)
        is Byte -> NativeAwsCliValue.Integer(value = toLong())
        is Short -> NativeAwsCliValue.Integer(value = toLong())
        is Int -> NativeAwsCliValue.Integer(value = toLong())
        is Long -> NativeAwsCliValue.Integer(value = this)
        is UByte -> NativeAwsCliValue.UnsignedInteger(value = toULong())
        is UShort -> NativeAwsCliValue.UnsignedInteger(value = toULong())
        is UInt -> NativeAwsCliValue.UnsignedInteger(value = toULong())
        is ULong -> NativeAwsCliValue.UnsignedInteger(value = this)
        is Float ->
            if (isFinite()) {
                NativeAwsCliValue.Number(value = toDouble())
            } else {
                NativeAwsCliValue.Unsupported(typeName = "non-finite floating-point number")
            }
        is Double ->
            if (isFinite()) {
                NativeAwsCliValue.Number(value = this)
            } else {
                NativeAwsCliValue.Unsupported(typeName = "non-finite floating-point number")
            }
        is String -> NativeAwsCliValue.String(value = this)
        is ByteArray -> NativeAwsCliValue.Bytes(value = this)
        is java.time.temporal.TemporalAccessor -> NativeAwsCliValue.String(value = toString())
        is Map<*, *> -> {
            if (keys.any { it !is String }) {
                NativeAwsCliValue.Unsupported(typeName = "mapping with non-string keys")
            } else {
                NativeAwsCliValue.Object(
                    entries = entries.associate { (key, value) -> key as String to value.toNativeAwsCliValue() },
                )
            }
        }
        is Iterable<*> -> NativeAwsCliValue.Array(items = map { it.toNativeAwsCliValue() })
        is Array<*> -> NativeAwsCliValue.Array(items = map { it.toNativeAwsCliValue() })
        else -> NativeAwsCliValue.Unsupported(typeName = javaClass.name)
    }

/**
 * Reads a resource provider schema file into an [AdditionalSchemaSource] for
 * [SchemaValidatorConfig.additionalSchemas]. [typeName] may be omitted when the
 * schema file contains its own `typeName` field.
 */
fun fileToAdditionalSchemaSource(file: File, typeName: String? = null): AdditionalSchemaSource =
    AdditionalSchemaSource(typeName = typeName, schema = file.readText())

/**
 * Reads a rule file into an [ExternalRuleSource] for [EngineConfig.customRules],
 * [EngineConfig.guardRules], [CompositeEngineConfig.regoRules], or
 * [CompositeEngineConfig.guardRules]. The file path becomes the rule source name -
 * the file-based counterpart to passing a template [File] to [Engine.validateTemplate].
 */
fun fileToExternalRuleSource(file: File): ExternalRuleSource =
    ExternalRuleSource(name = file.path, content = file.readText())

class TemplateModel(template: File) {
    private val inner = JvmSemanticModel.parse(template.readBytes())

    fun resources() = inner.resources()
    fun parameters() = inner.parameters()
    fun outputs() = inner.outputs()
    fun conditions() = inner.conditions()
    fun transforms() = inner.transforms()
    fun formatVersion() = inner.formatVersion()
    fun description() = inner.description()
    fun toDiagnosticModel() = inner.toDiagnosticModel()
    fun sourceLocation(path: String) = inner.sourceLocation(path)
}

class SchemaValidator(config: SchemaValidatorConfig = SchemaValidatorConfig()) {
    private val inner = JvmSchemaValidator(config)

    fun listRules(): List<RuleInfo> = inner.listRules()
    fun schemaCount(): Int = inner.schemaCount().toInt()

    fun validate(template: File, region: String?): List<Diagnostic> {
        val model = JvmSemanticModel.parse(template.readBytes())
        return inner.validate(model, region).diagnostics
    }
}

class RegoEngine(
    config: EngineConfig = EngineConfig(),
) : Engine {
    private val inner = JvmRegoEngine(config)

    override fun validateTemplate(template: File, config: ValidateConfig): ValidationReport =
        inner.validateTemplate(template.readBytes(), config, template.path)

    override fun validateAwsCliCommand(
        request: AwsCliCommand,
        config: ValidateConfig,
    ): AwsCliCommandValidation = inner.validateAwsCliCommand(request.toNative(), config)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}

class CelEngine(
    config: EngineConfig = EngineConfig(),
) : Engine {
    private val inner = JvmCelEngine(config)

    override fun validateTemplate(template: File, config: ValidateConfig): ValidationReport =
        inner.validateTemplate(template.readBytes(), config, template.path)

    override fun validateAwsCliCommand(
        request: AwsCliCommand,
        config: ValidateConfig,
    ): AwsCliCommandValidation = inner.validateAwsCliCommand(request.toNative(), config)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}

/**
 * Evaluates the built-in rules together with any caller-supplied external rules,
 * returning one merged report. Configured with [CompositeEngineConfig], which
 * carries only the external rules layered on top of the built-ins - not the
 * engine-native `customRules` field of [EngineConfig].
 */
class CompositeEngine(
    config: CompositeEngineConfig = CompositeEngineConfig(),
) : Engine {
    private val inner = JvmCompositeEngine(config)

    override fun validateTemplate(template: File, config: ValidateConfig): ValidationReport =
        inner.validateTemplate(template.readBytes(), config, template.path)

    override fun validateAwsCliCommand(
        request: AwsCliCommand,
        config: ValidateConfig,
    ): AwsCliCommandValidation = inner.validateAwsCliCommand(request.toNative(), config)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}
