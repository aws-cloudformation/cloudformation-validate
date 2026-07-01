/**
 * Minimal example: validate a CloudFormation template with the JVM bindings.
 *
 * Run from this directory with:  gradle run
 * Optionally pass a template path: gradle run --args="path/to/template.yaml"
 */
import com.amazonaws.cloudformation.validation.RegoEngine
import java.io.File

fun main(args: Array<String>) {
    val template = if (args.isNotEmpty()) File(args[0]) else File("template.yaml")

    // RegoEngine and CelEngine are interchangeable — both produce identical diagnostics.
    val engine = RegoEngine()
    val report = engine.validateStandard(template)

    println("${report.filePath}: ${report.status}")
    for (d in report.diagnostics) {
        val where = d.resourceId?.let { " ($it)" } ?: ""
        println("  [${d.severity}] ${d.ruleId}$where: ${d.message}")
    }

    val counts = report.metadata.counts
    println(
        "\n${report.diagnostics.size} diagnostic(s): " +
            "${counts.fatal} fatal, ${counts.errors} error, ${counts.warnings} warn, ${counts.informational} info",
    )
}
