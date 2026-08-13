import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import software.amazon.cloudformation.validate.CelEngine
import software.amazon.cloudformation.validate.RegoEngine
import software.amazon.cloudformation.validate.ValidateConfig
import software.amazon.cloudformation.validate.ValidationException
import software.amazon.cloudformation.validate.engine.EngineConfig
import software.amazon.cloudformation.validate.rules.Severity
import java.io.File
import java.time.Duration

class SecurityTest {
    @TestFactory
    fun everySecurityTemplateWithBothEngines(): List<DynamicTest> {
        val templates =
            securityRoot
                .walkTopDown()
                .filter { it.isFile && it.extension.lowercase() in setOf("json", "yaml", "yml") }
                .sortedBy { it.path }
                .toList()
        check(templates.isNotEmpty()) { "no security templates found under ${securityRoot.path}" }

        val config = ValidateConfig(severityLevel = Severity.DEBUG)
        return listOf("rego", "cel").flatMap { engineName ->
            templates.map { template ->
                val relativePath = template.relativeTo(securityRoot).path.replace('\\', '/')
                DynamicTest.dynamicTest("$engineName/$relativePath") {
                    assertTimeoutPreemptively(Duration.ofSeconds(60)) {
                        val engine: Any =
                            if (engineName == "rego") {
                                RegoEngine(EngineConfig())
                            } else {
                                CelEngine(EngineConfig())
                            }
                        try {
                            val report =
                                when (engine) {
                                    is RegoEngine -> engine.validateDetailed(template, config)
                                    is CelEngine -> engine.validateDetailed(template, config)
                                    else -> error("unsupported engine type")
                                }
                            assertNotNull(report.status)
                            assertNotNull(report.diagnostics)
                        } catch (error: ValidationException) {
                            assertTrue(
                                relativePath == "deep_nesting.json" && !error.message.isNullOrEmpty(),
                                "$engineName/$relativePath returned an unexpected error: ${error.message}",
                            )
                        }
                    }
                }
            }
        }
    }

    companion object {
        private val resourcesRoot =
            listOf(
                File("${System.getProperty("user.dir")}/../../resources"),
                File("${System.getProperty("user.dir")}/../../../resources"),
            ).first { it.exists() }
        private val securityRoot = File(resourcesRoot, "security")
    }
}
