import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const {
    RegoEngine,
    CelEngine,
    SchemaValidator,
    TemplateModel,
    TemplateFile,
    version,
} = require('@aws/cloudformation-validate');

const TEMPLATES_ROOT = path.resolve(__dirname, "../../resources/templates");
const RULES_DIR = path.resolve(__dirname, "../../resources/rules");
const EXPECTED_DIR = path.resolve(__dirname, "../../resources/expected");

function loadTemplate(rel: string): InstanceType<typeof TemplateFile> {
  return new TemplateFile(path.join(TEMPLATES_ROOT, rel));
}

function loadRule(filename: string): string {
  return fs.readFileSync(path.join(RULES_DIR, filename), "utf-8");
}

const COMBINED_GOLDEN: Record<string, unknown> = JSON.parse(
  fs.readFileSync(path.join(EXPECTED_DIR, "all_templates.json"), "utf-8")
);

const GOLDEN_DIRS = ['bad', 'cdk', 'good', 'gh-issues', 'integration', 'issues', 'lsp', 'public', 'quickstart'];

function discoverAllTemplates(): string[] {
  const templates: string[] = [];
  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(yaml|yml|json)$/.test(entry.name)) {
        templates.push(path.relative(TEMPLATES_ROOT, full));
      }
    }
  }
  for (const sub of GOLDEN_DIRS) {
    const dir = path.join(TEMPLATES_ROOT, sub);
    if (fs.existsSync(dir)) walk(dir);
  }
  return templates.sort();
}

const EXPECTED_TEMPLATES = discoverAllTemplates();

const FULL_ONLY_DIAGNOSTIC_FIELDS = ["documentationUrl", "context", "ruleDescription", "phase", "section"];

const CEL = new CelEngine();
const REGO = new RegoEngine();

function loadGolden(rel: string): unknown {
  return COMBINED_GOLDEN[rel];
}

function stripGoldenExcludedFields(report: any, filePath?: string): unknown {
  const clone = JSON.parse(JSON.stringify(report));
  if (filePath !== undefined) {
    clone.filePath = filePath;
  }
  delete clone.engineVersion;
  delete clone.performance;
  if (clone.metadata && typeof clone.metadata === "object") {
    delete clone.metadata.rulesEvaluated;
  }
  return clone;
}

// ── version ──────────────────────────────────────────────────────────────────

function readWorkspaceVersion(): string {
  const cargoTomlPath = path.resolve(__dirname, "../../Cargo.toml");
  const lines = fs.readFileSync(cargoTomlPath, "utf-8").split("\n");
  let inWorkspacePackage = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "[workspace.package]") {
      inWorkspacePackage = true;
      continue;
    }
    if (inWorkspacePackage && trimmed.startsWith("[")) {
      break;
    }
    if (inWorkspacePackage && trimmed.startsWith("version = ")) {
      const value = trimmed.slice("version = ".length).trim();
      if (!value.startsWith("\"") || !value.endsWith("\"")) {
        throw new Error(`malformed version line in ${cargoTomlPath}: ${line}`);
      }
      return value.slice(1, -1);
    }
  }
  throw new Error(`missing 'version = ' under [workspace.package] in ${cargoTomlPath}`);
}

describe("version", () => {
  it("returns the crate version from workspace Cargo.toml", () => {
    expect(version()).toBe(readWorkspaceVersion());
  });
});

// ── Engine construction ──────────────────────────────────────────────────────

describe("engine construction", () => {
  it("CelEngine reports name 'cel'", () => {
    const engine = new CelEngine();
    expect(engine.engineName()).toBe("cel");
    engine.free();
  });

  it("RegoEngine reports name 'rego'", () => {
    const engine = new RegoEngine();
    expect(engine.engineName()).toBe("rego");
    engine.free();
  });
});

// ── SchemaValidator ──────────────────────────────────────────────────────────

describe("SchemaValidator", () => {
  it("exposes schemas and rules", () => {
    const sv = new SchemaValidator();
    expect(sv.schemaCount()).toBeGreaterThan(0);
    const rules = sv.listRules();
    expect(rules.length).toBeGreaterThan(0);
    expect(rules[0].id).toBeDefined();
    sv.free();
  });
});

// ── listRules ────────────────────────────────────────────────────────────────

describe("listRules", () => {
  it("CelEngine rules are sorted by id", () => {
    const ids = CEL.listRules().map((r: any) => r.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(ids).toEqual([...ids].sort());
  });

  it("RegoEngine rules are sorted by id", () => {
    const ids = REGO.listRules().map((r: any) => r.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(ids).toEqual([...ids].sort());
  });

  it("CelEngine and RegoEngine list identical rules", () => {
    const celRules = CEL.listRules();
    const regoRules = REGO.listRules();
    expect(celRules).toEqual(regoRules);
  });
});

// ── TemplateModel (SemanticModel) ────────────────────────────────────────────

describe("TemplateModel", () => {
  it("parses format version and resources from minimal template", () => {
    const model = new TemplateModel(loadTemplate("good/minimal.yaml"));
    expect(model.formatVersion()).toBe("2010-09-09");
    const resources = model.resources();
    expect(Object.keys(resources)).toContain("IamPipeline");
    model.free();
  });

  it("parses description, conditions, and outputs from generic template", () => {
    const model = new TemplateModel(loadTemplate("good/generic.yaml"));
    expect(model.description()).toBe("A sample template");
    expect(model.conditions()).toContain("ProdVolumeSize");
    expect(model.outputs()).toHaveProperty("ElasticIP");
    model.free();
  });

  it("toDiagnosticModel returns template and resources sections", () => {
    const model = new TemplateModel(loadTemplate("good/generic.yaml"));
    const json = model.toDiagnosticModel();
    expect(json).toHaveProperty("template");
    expect(json).toHaveProperty("resources");
    model.free();
  });

  it("rejects malformed YAML", () => {
    expect(() => new TemplateModel(loadTemplate("malformed.yaml"))).toThrow();
  });

  it("minimal template has no conditions or transforms", () => {
    const model = new TemplateModel(loadTemplate("good/minimal.yaml"));
    expect(model.transforms()).toHaveLength(0);
    expect(model.conditions()).toHaveLength(0);
    model.free();
  });
});

// ── Invalid input ────────────────────────────────────────────────────────────

describe("invalid input", () => {
  it("CelEngine returns F1101 for empty template", () => {
    const report = CEL.validateStandard(loadTemplate("empty.yaml"));
    expect(report.status).toBe("ERROR");
    expect(report.diagnostics[0].ruleId).toBe("F1101");
    expect(report.diagnostics[0].severity).toBe("FATAL");
  });

  it("RegoEngine returns F1101 for empty template", () => {
    const report = REGO.validateStandard(loadTemplate("empty.yaml"));
    expect(report.status).toBe("ERROR");
    expect(report.diagnostics[0].ruleId).toBe("F1101");
    expect(report.diagnostics[0].severity).toBe("FATAL");
  });
});

// ── Custom rules: 1 file, 1 rule ────────────────────────────────────────────

describe("custom rule", () => {
  it("listRules and validate match between engines with explicit values", () => {
    const cel = new CelEngine({
      customRules: [{ name: "cel_custom.json", content: loadRule("cel_custom.json") }],
    });
    const rego = new RegoEngine({
      customRules: [{ name: "rego_custom.rego", content: loadRule("rego_custom.rego") }],
    });

    for (const [name, engine] of [["cel", cel], ["rego", rego]] as const) {
      const report = (engine as any).validateStandard(loadTemplate("bad/invalid_deletion_policy.yaml"));
      const d = report.diagnostics.find((d: any) => d.ruleId === "CUSTOM001");
      expect(d, `${name}: CUSTOM001 diagnostic must fire`).toBeDefined();
      expect(d.severity).toBe("ERROR");
      expect(d.resourceId).toBe("Bucket");
      expect(d.resourceType).toBe("AWS::S3::Bucket");
    }

    const baselineCount = CEL.listRules().length;
    for (const [name, engine] of [["cel", cel], ["rego", rego]] as const) {
      const rules = (engine as any).listRules();
      const c = rules.find((r: any) => r.id === "CUSTOM001");
      expect(c, `${name}: CUSTOM001 must exist`).toBeDefined();
      expect(c.severity).toBe("ERROR");
      expect(c.origin).toBe("CUSTOM");
      expect(c.description).toBe("S3 bucket must have encryption configured");
      expect(rules.filter((r: any) => r.origin !== "CUSTOM").length).toBe(baselineCount);
    }

    expect(cel.listRules()).toEqual(rego.listRules());
    cel.free(); rego.free();
  });
});

// ── Guard rules: 1 file, 1 rule ─────────────────────────────────────────────

describe("guard rule", () => {
  it("listRules and validate match between engines with explicit values", () => {
    const cel = new CelEngine({
      guardRules: [{ name: "guard_encryption.guard", content: loadRule("guard_encryption.guard") }],
    });
    const rego = new RegoEngine({
      guardRules: [{ name: "guard_encryption.guard", content: loadRule("guard_encryption.guard") }],
    });

    const baselineCount = CEL.listRules().length;
    for (const [name, engine] of [["cel", cel], ["rego", rego]] as const) {
      const rules = (engine as any).listRules();
      const g = rules.find((r: any) => r.id === "check_bucket_encryption");
      expect(g, `${name}: check_bucket_encryption must exist`).toBeDefined();
      expect(g.severity).toBe("ERROR");
      expect(g.origin).toBe("GUARD");
      expect(g.description).toBe("S3 bucket must have encryption configured");
      expect(rules.filter((r: any) => r.origin !== "GUARD").length).toBe(baselineCount);

      const report = (engine as any).validateStandard(loadTemplate("bad/invalid_deletion_policy.yaml"));
      const d = report.diagnostics.find((d: any) => d.ruleId === "check_bucket_encryption");
      expect(d, `${name}: check_bucket_encryption diagnostic must fire`).toBeDefined();
      expect(d.severity).toBe("ERROR");
      expect(d.source).toBe("GUARD");
      expect(d.resourceId).toBe("Bucket");
    }

    expect(cel.listRules()).toEqual(rego.listRules());
    cel.free(); rego.free();
  });
});

// ── Combined: 1 custom file + 1 guard file ──────────────────────────────────

describe("single combined custom + guard", () => {
  it("listRules and validate match between engines with explicit values", () => {
    const cel = new CelEngine({
      customRules: [{ name: "cel_custom.json", content: loadRule("cel_custom.json") }],
      guardRules: [{ name: "guard_encryption.guard", content: loadRule("guard_encryption.guard") }],
    });
    const rego = new RegoEngine({
      customRules: [{ name: "rego_custom.rego", content: loadRule("rego_custom.rego") }],
      guardRules: [{ name: "guard_encryption.guard", content: loadRule("guard_encryption.guard") }],
    });

    // Rego discovers custom rule metadata during evaluation.
    rego.validateStandard(loadTemplate("bad/invalid_deletion_policy.yaml"));

    for (const [name, engine] of [["cel", cel], ["rego", rego]] as const) {
      const rules = (engine as any).listRules();
      expect(rules.find((r: any) => r.id === "CUSTOM001")?.origin).toBe("CUSTOM");
      expect(rules.find((r: any) => r.id === "check_bucket_encryption")?.origin).toBe("GUARD");
      const ids = rules.map((r: any) => r.id);
      expect(ids).toEqual([...ids].sort());
    }

    expect(cel.listRules()).toEqual(rego.listRules());
    cel.free(); rego.free();
  });
});

// ── Multi: 2 custom rules + 2 guard files (1 rule + 2 rules) ────────────────

describe("multi combined custom + guard", () => {
  it("listRules match between engines with explicit values for all rules", () => {
    const cel = new CelEngine({
      customRules: [{ name: "cel_multi_custom.json", content: loadRule("cel_multi_custom.json") }],
      guardRules: [
        { name: "guard_encryption.guard", content: loadRule("guard_encryption.guard") },
        { name: "guard_multi.guard", content: loadRule("guard_multi.guard") },
      ],
    });
    const rego = new RegoEngine({
      customRules: [{ name: "rego_multi_custom.rego", content: loadRule("rego_multi_custom.rego") }],
      guardRules: [
        { name: "guard_encryption.guard", content: loadRule("guard_encryption.guard") },
        { name: "guard_multi.guard", content: loadRule("guard_multi.guard") },
      ],
    });

    // Rego discovers custom rule metadata during evaluation.
    rego.validateStandard(loadTemplate("bad/invalid_deletion_policy.yaml"));

    for (const [name, engine] of [["cel", cel], ["rego", rego]] as const) {
      const rules = (engine as any).listRules();

      const c1 = rules.find((r: any) => r.id === "CUSTOM010");
      expect(c1, `${name}: CUSTOM010`).toBeDefined();
      expect(c1.severity).toBe("ERROR");
      expect(c1.origin).toBe("CUSTOM");
      expect(c1.description).toBe("S3 bucket must have versioning enabled");

      const c2 = rules.find((r: any) => r.id === "CUSTOM011");
      expect(c2, `${name}: CUSTOM011`).toBeDefined();
      expect(c2.severity).toBe("WARN");
      expect(c2.origin).toBe("CUSTOM");
      expect(c2.description).toBe("S3 bucket should have lifecycle rules configured");

      const enc = rules.find((r: any) => r.id === "check_bucket_encryption");
      expect(enc, `${name}: check_bucket_encryption`).toBeDefined();
      expect(enc.origin).toBe("GUARD");
      expect(enc.description).toBe("S3 bucket must have encryption configured");

      const ver = rules.find((r: any) => r.id === "check_bucket_versioning");
      expect(ver, `${name}: check_bucket_versioning`).toBeDefined();
      expect(ver.origin).toBe("GUARD");
      expect(ver.description).toBe("S3 bucket must have versioning enabled");

      const lc = rules.find((r: any) => r.id === "check_bucket_lifecycle");
      expect(lc, `${name}: check_bucket_lifecycle`).toBeDefined();
      expect(lc.origin).toBe("GUARD");
      expect(lc.description).toBe("S3 bucket should have lifecycle rules configured");

      const ids = rules.map((r: any) => r.id);
      expect(ids).toEqual([...ids].sort());
    }

    expect(cel.listRules()).toEqual(rego.listRules());
    cel.free(); rego.free();
  });
});

// ── Golden file validation ───────────────────────────────────────────────────

function stripDetailedOnlyFields(report: any): unknown {
  const clone = JSON.parse(JSON.stringify(report));
  if (clone.diagnostics) {
    for (const d of clone.diagnostics) {
      for (const field of FULL_ONLY_DIAGNOSTIC_FIELDS) {
        delete d[field];
      }
    }
  }
  return clone;
}

describe("golden file validation", () => {
  function detailedTests(engineName: string, engine: any) {
    describe(`${engineName} detailed matches golden`, () => {
      for (const rel of EXPECTED_TEMPLATES) {
        it(rel, () => {
          const actual = engine.validateDetailed(loadTemplate(rel), { severityLevel: "DEBUG" });
          expect(stripGoldenExcludedFields(actual, rel)).toEqual(stripGoldenExcludedFields(loadGolden(rel)));
        });
      }
    });
  }

  function standardTests(engineName: string, engine: any) {
    describe(`${engineName} standard matches golden`, () => {
      for (const rel of EXPECTED_TEMPLATES) {
        it(rel, () => {
          const actual = engine.validateStandard(loadTemplate(rel), { severityLevel: "DEBUG" });
          expect(stripGoldenExcludedFields(actual, rel)).toEqual(stripGoldenExcludedFields(stripDetailedOnlyFields(loadGolden(rel))));
        });
      }
    });
  }

  detailedTests("rego", REGO);
  standardTests("rego", REGO);
  detailedTests("cel", CEL);
  standardTests("cel", CEL);
});

describe("report fields excluded from golden", () => {
  const REPORT_TEMPLATE = "good/generic.yaml";

  const EXPECTED_RULES_EVALUATED = 279;
  const EXPECTED_ENGINE_VERSION = "1.4.0";

  it("rulesEvaluated is the full built-in rule count under both engines", () => {
    for (const [name, engine] of [["cel", CEL], ["rego", REGO]] as const) {
      const report = (engine as any).validateDetailed(loadTemplate(REPORT_TEMPLATE), { severityLevel: "DEBUG" });
      expect(report.metadata.rulesEvaluated, `${name}: rulesEvaluated`).toBe(EXPECTED_RULES_EVALUATED);
    }
  });

  it("engineVersion is the workspace crate version under both engines", () => {
    expect(EXPECTED_ENGINE_VERSION, "expected version must match workspace Cargo.toml").toBe(readWorkspaceVersion());
    for (const [name, engine] of [["cel", CEL], ["rego", REGO]] as const) {
      const report = (engine as any).validateDetailed(loadTemplate(REPORT_TEMPLATE), { severityLevel: "DEBUG" });
      expect(report.engineVersion, `${name}: engineVersion`).toBe(EXPECTED_ENGINE_VERSION);
    }
  });

  it("performance is present with a timing metric per phase", () => {
    const report = REGO.validateDetailed(loadTemplate(REPORT_TEMPLATE), { severityLevel: "DEBUG" });
    const phases = [
      "schemaInit",
      "engineInit",
      "modelBuild",
      "schemaValidate",
      "ruleEvaluation",
      "diagnosticFinalize",
      "validateTotal",
    ];
    expect(report.performance).toBeDefined();
    for (const phase of phases) {
      expect(typeof report.performance[phase].durationMs, `performance.${phase}.durationMs`).toBe("number");
    }
  });
});
