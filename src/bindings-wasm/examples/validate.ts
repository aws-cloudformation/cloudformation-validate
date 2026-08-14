/**
 * Minimal example: validate a CloudFormation template with the WASM bindings.
 *
 * Run from this directory with:  npm install && npm start
 * Optionally pass a template path: npm start -- path/to/template.yaml
 */
import * as path from 'path';
import { RegoEngine, TemplateFile } from '@aws/cloudformation-validate';

const templatePath = process.argv[2] ?? path.join(__dirname, 'template.yaml');

// RegoEngine and CelEngine are interchangeable - both produce identical diagnostics.
const engine = new RegoEngine();
try {
    const report = engine.validateStandard(new TemplateFile(templatePath));

    console.log(`${report.filePath}: ${report.status}`);
    for (const d of report.diagnostics) {
        const where = d.entity ? ` (${d.entity.logicalId})` : '';
        console.log(`  [${d.severity}] ${d.ruleId}${where}: ${d.message}`);
    }

    const { counts } = report.metadata;
    console.log(
        `\n${report.diagnostics.length} diagnostic(s): ` +
            `${counts.fatal} fatal, ${counts.errors} error, ${counts.warnings} warn, ${counts.informational} info`,
    );
} finally {
    // WASM objects must be freed explicitly to release memory.
    engine.free();
}
