package software.amazon.cloudformation.validate

import software.amazon.cloudformation.validate.datasource.AdditionalSchemaSource
import software.amazon.cloudformation.validate.diagnostics.DetailedReport
import software.amazon.cloudformation.validate.diagnostics.StandardDiagnostic
import software.amazon.cloudformation.validate.diagnostics.StandardReport
import software.amazon.cloudformation.validate.engine.AwsApiRequestContext as NativeAwsApiRequest
import software.amazon.cloudformation.validate.engine.AwsApiRequestValidation
import software.amazon.cloudformation.validate.engine.AwsApiValue as NativeAwsApiValue
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.engine.ExternalRuleSource
import software.amazon.cloudformation.validate.rules.RuleInfo
import software.amazon.cloudformation.validate.schemavalidator.SchemaValidatorConfig
import java.io.File

interface Engine {
    fun validateStandard(template: File, config: ValidateConfig = ValidateConfig()): StandardReport
    fun validateDetailed(template: File, config: ValidateConfig = ValidateConfig()): DetailedReport
    fun validateAwsApiRequest(
        request: AwsApiRequest,
        config: ValidateConfig = ValidateConfig(),
    ): AwsApiRequestValidation
    fun listRules(): List<RuleInfo>
    fun engineName(): String
}

/**
 * Service, operation, and request values for CloudFormation validation.
 *
 * [parameters] accepts nested maps/lists, strings, numbers, booleans, nulls,
 * byte arrays, and Java time values. Unsupported values are marked explicitly
 * and conservatively omitted during request-to-template synthesis.
 */
class AwsApiRequest @JvmOverloads constructor(
    val serviceName: String,
    val operationName: String,
    parameters: Map<String, Any?>,
    val servicePrefix: String? = null,
    val httpMethod: String? = null,
    val isReadOnly: Boolean? = null,
) {
    val parameters: Map<String, Any?> = LinkedHashMap(parameters)

    internal fun toNative(): NativeAwsApiRequest =
        NativeAwsApiRequest(
            serviceName = serviceName,
            operationName = operationName,
            parameters = parameters.mapValues { (_, value) -> value.toNativeAwsApiValue() },
            servicePrefix = servicePrefix,
            httpMethod = httpMethod,
            isReadOnly = isReadOnly,
        )
}

private fun Any?.toNativeAwsApiValue(): NativeAwsApiValue =
    when (this) {
        null -> NativeAwsApiValue.Null
        is Boolean -> NativeAwsApiValue.Boolean(value = this)
        is Byte -> NativeAwsApiValue.Integer(value = toLong())
        is Short -> NativeAwsApiValue.Integer(value = toLong())
        is Int -> NativeAwsApiValue.Integer(value = toLong())
        is Long -> NativeAwsApiValue.Integer(value = this)
        is UByte -> NativeAwsApiValue.UnsignedInteger(value = toULong())
        is UShort -> NativeAwsApiValue.UnsignedInteger(value = toULong())
        is UInt -> NativeAwsApiValue.UnsignedInteger(value = toULong())
        is ULong -> NativeAwsApiValue.UnsignedInteger(value = this)
        is Float ->
            if (isFinite()) {
                NativeAwsApiValue.Number(value = toDouble())
            } else {
                NativeAwsApiValue.Unsupported(typeName = "non-finite floating-point number")
            }
        is Double ->
            if (isFinite()) {
                NativeAwsApiValue.Number(value = this)
            } else {
                NativeAwsApiValue.Unsupported(typeName = "non-finite floating-point number")
            }
        is String -> NativeAwsApiValue.String(value = this)
        is ByteArray -> NativeAwsApiValue.Bytes(value = this)
        is java.time.temporal.TemporalAccessor -> NativeAwsApiValue.String(value = toString())
        is Map<*, *> -> {
            if (keys.any { it !is String }) {
                NativeAwsApiValue.Unsupported(typeName = "mapping with non-string keys")
            } else {
                NativeAwsApiValue.Object(
                    entries = entries.associate { (key, value) -> key as String to value.toNativeAwsApiValue() },
                )
            }
        }
        is Iterable<*> -> NativeAwsApiValue.Array(items = map { it.toNativeAwsApiValue() })
        is Array<*> -> NativeAwsApiValue.Array(items = map { it.toNativeAwsApiValue() })
        else -> NativeAwsApiValue.Unsupported(typeName = javaClass.name)
    }

/**
 * Reads a resource provider schema file into an [AdditionalSchemaSource] for
 * [SchemaValidatorConfig.additionalSchemas]. [typeName] may be omitted when the
 * schema file contains its own `typeName` field.
 */
fun fileToAdditionalSchemaSource(file: File, typeName: String? = null): AdditionalSchemaSource =
    AdditionalSchemaSource(typeName = typeName, schema = file.readText())

/**
 * Reads a rule file into an [ExternalRuleSource] for [EngineConfig.customRules] or
 * [EngineConfig.guardRules]. The file path becomes the rule source name - the file-based
 * counterpart to passing a template [File] to [Engine.validateStandard].
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

    fun validate(template: File, region: String?): List<StandardDiagnostic> {
        val model = JvmSemanticModel.parse(template.readBytes())
        return inner.validate(model, region).diagnostics
    }
}

class RegoEngine(
    config: EngineConfig = EngineConfig(),
) : Engine {
    private val inner = JvmRegoEngine(config)

    override fun validateStandard(template: File, config: ValidateConfig): StandardReport =
        inner.validateStandard(template.readBytes(), config, template.path)

    override fun validateDetailed(template: File, config: ValidateConfig): DetailedReport =
        inner.validateDetailed(template.readBytes(), config, template.path)

    override fun validateAwsApiRequest(
        request: AwsApiRequest,
        config: ValidateConfig,
    ): AwsApiRequestValidation = inner.validateAwsApiRequest(request.toNative(), config)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}

class CelEngine(
    config: EngineConfig = EngineConfig(),
) : Engine {
    private val inner = JvmCelEngine(config)

    override fun validateStandard(template: File, config: ValidateConfig): StandardReport =
        inner.validateStandard(template.readBytes(), config, template.path)

    override fun validateDetailed(template: File, config: ValidateConfig): DetailedReport =
        inner.validateDetailed(template.readBytes(), config, template.path)

    override fun validateAwsApiRequest(
        request: AwsApiRequest,
        config: ValidateConfig,
    ): AwsApiRequestValidation = inner.validateAwsApiRequest(request.toNative(), config)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}
