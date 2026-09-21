package software.amazon.cloudformation.validate

import software.amazon.cloudformation.validate.diagnostics.DetailLevel
import software.amazon.cloudformation.validate.engine.CompositeEngineConfig
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.engine.ExternalRuleSource
import software.amazon.cloudformation.validate.rules.IdRange
import software.amazon.cloudformation.validate.rules.LogicalIdFilter
import software.amazon.cloudformation.validate.rules.ResourceIdFilter
import software.amazon.cloudformation.validate.rules.ResourceTypeFilter
import software.amazon.cloudformation.validate.rules.RuleFilterConfig
import software.amazon.cloudformation.validate.rules.ServiceFilter
import software.amazon.cloudformation.validate.rules.Severity
import software.amazon.cloudformation.validate.schemavalidator.SchemaValidatorConfig
import software.amazon.cloudformation.validate.templatemodel.PseudoParameterOverrides

/*
 * Java sees only each generated config record's full positional constructor, so these builders
 * set one field at a time. They go through copy() so the defaults stay defined once, in the record.
 */

class ValidateConfigBuilder {
    private var config = ValidateConfig()

    fun include(include: RuleFilterConfig): ValidateConfigBuilder = apply { config = config.copy(include = include) }

    fun exclude(exclude: RuleFilterConfig): ValidateConfigBuilder = apply { config = config.copy(exclude = exclude) }

    fun detailLevel(detailLevel: DetailLevel?): ValidateConfigBuilder = apply { config = config.copy(detailLevel = detailLevel) }

    fun severityLevel(severityLevel: Severity?): ValidateConfigBuilder = apply { config = config.copy(severityLevel = severityLevel) }

    fun parameterOverrides(parameterOverrides: Map<String, String>): ValidateConfigBuilder = apply { config = config.copy(parameterOverrides = parameterOverrides) }

    fun pseudoParameterOverrides(pseudoParameterOverrides: PseudoParameterOverrides): ValidateConfigBuilder = apply { config = config.copy(pseudoParameterOverrides = pseudoParameterOverrides) }

    fun strict(strict: Boolean?): ValidateConfigBuilder = apply { config = config.copy(strict = strict) }

    fun disableBuiltinRules(disableBuiltinRules: Boolean?): ValidateConfigBuilder = apply { config = config.copy(disableBuiltinRules = disableBuiltinRules) }

    fun build(): ValidateConfig = config
}

class RuleFilterConfigBuilder {
    private var filter = RuleFilterConfig()

    fun ids(ids: List<String>): RuleFilterConfigBuilder = apply { filter = filter.copy(ids = ids) }

    fun categories(categories: List<String>): RuleFilterConfigBuilder = apply { filter = filter.copy(categories = categories) }

    fun idRanges(idRanges: List<IdRange>): RuleFilterConfigBuilder = apply { filter = filter.copy(idRanges = idRanges) }

    fun idPatterns(idPatterns: List<String>): RuleFilterConfigBuilder = apply { filter = filter.copy(idPatterns = idPatterns) }

    fun resourceIds(resourceIds: List<ResourceIdFilter>): RuleFilterConfigBuilder = apply { filter = filter.copy(resourceIds = resourceIds) }

    fun logicalIds(logicalIds: List<LogicalIdFilter>): RuleFilterConfigBuilder = apply { filter = filter.copy(logicalIds = logicalIds) }

    fun resourceTypes(resourceTypes: List<ResourceTypeFilter>): RuleFilterConfigBuilder = apply { filter = filter.copy(resourceTypes = resourceTypes) }

    fun services(services: List<ServiceFilter>): RuleFilterConfigBuilder = apply { filter = filter.copy(services = services) }

    fun build(): RuleFilterConfig = filter
}

class PseudoParameterOverridesBuilder {
    private var overrides = PseudoParameterOverrides()

    fun accountId(accountId: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(accountId = accountId) }

    fun notificationArns(notificationArns: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(notificationArns = notificationArns) }

    fun partition(partition: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(partition = partition) }

    fun region(region: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(region = region) }

    fun stackId(stackId: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(stackId = stackId) }

    fun stackName(stackName: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(stackName = stackName) }

    fun urlSuffix(urlSuffix: String?): PseudoParameterOverridesBuilder = apply { overrides = overrides.copy(urlSuffix = urlSuffix) }

    fun build(): PseudoParameterOverrides = overrides
}

class EngineConfigBuilder {
    private var config = EngineConfig()

    fun customRules(customRules: List<ExternalRuleSource>): EngineConfigBuilder = apply { config = config.copy(customRules = customRules) }

    fun guardRules(guardRules: List<ExternalRuleSource>): EngineConfigBuilder = apply { config = config.copy(guardRules = guardRules) }

    fun schemaValidatorConfig(schemaValidatorConfig: SchemaValidatorConfig?): EngineConfigBuilder = apply { config = config.copy(schemaValidatorConfig = schemaValidatorConfig) }

    fun build(): EngineConfig = config
}

class CompositeEngineConfigBuilder {
    private var config = CompositeEngineConfig()

    fun regoRules(regoRules: List<ExternalRuleSource>): CompositeEngineConfigBuilder = apply { config = config.copy(regoRules = regoRules) }

    fun celRules(celRules: List<ExternalRuleSource>): CompositeEngineConfigBuilder = apply { config = config.copy(celRules = celRules) }

    fun guardRules(guardRules: List<ExternalRuleSource>): CompositeEngineConfigBuilder = apply { config = config.copy(guardRules = guardRules) }

    fun schemaValidatorConfig(schemaValidatorConfig: SchemaValidatorConfig?): CompositeEngineConfigBuilder = apply { config = config.copy(schemaValidatorConfig = schemaValidatorConfig) }

    fun build(): CompositeEngineConfig = config
}
