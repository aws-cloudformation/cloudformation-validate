package software.amazon.cloudformation.validate

import software.amazon.cloudformation.validate.diagnostics.DetailedReport
import software.amazon.cloudformation.validate.diagnostics.StandardDiagnostic
import software.amazon.cloudformation.validate.diagnostics.StandardReport
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.engine.ExternalRuleSource
import software.amazon.cloudformation.validate.rules.RuleInfo
import java.io.File

interface Engine {
    fun validateStandard(template: File, config: ValidateConfig = ValidateConfig()): StandardReport
    fun validateDetailed(template: File, config: ValidateConfig = ValidateConfig()): DetailedReport
    fun listRules(): List<RuleInfo>
    fun engineName(): String
}

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

class SchemaValidator {
    private val inner = JvmSchemaValidator()

    fun listRules(): List<RuleInfo> = inner.listRules()
    fun schemaCount(): Int = inner.schemaCount().toInt()

    fun validate(template: File, region: String?): List<StandardDiagnostic> {
        val model = JvmSemanticModel.parse(template.readBytes())
        return inner.validate(model, region).diagnostics
    }
}

class RegoEngine(config: EngineConfig = EngineConfig()) : Engine {
    private val inner = JvmRegoEngine(config)

    override fun validateStandard(template: File, config: ValidateConfig): StandardReport =
        inner.validateStandard(template.readBytes(), config, template.path)

    override fun validateDetailed(template: File, config: ValidateConfig): DetailedReport =
        inner.validateDetailed(template.readBytes(), config, template.path)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}

class CelEngine(config: EngineConfig = EngineConfig()) : Engine {
    private val inner = JvmCelEngine(config)

    override fun validateStandard(template: File, config: ValidateConfig): StandardReport =
        inner.validateStandard(template.readBytes(), config, template.path)

    override fun validateDetailed(template: File, config: ValidateConfig): DetailedReport =
        inner.validateDetailed(template.readBytes(), config, template.path)

    override fun listRules(): List<RuleInfo> = inner.listRules()
    override fun engineName(): String = inner.engineName()
}
