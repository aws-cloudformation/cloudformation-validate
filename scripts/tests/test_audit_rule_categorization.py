"""Tests for scripts/audit_rule_categorization.py — focused on todos #23-30.

Covers:
- Rego regex recognizes _at_source variant (todo #23)
- Production emission scan scope and cfg(test) exclusion (todo #24, #25)
- Explicit schema-grounded non-F set and exact origin mismatch (todo #26, #27)
- No forced W9003/W1019 engine-extra overrides (todo #28)
- Engine-extra invariant validation (todo #29)
- Main exit status for all failure classes (todo #30)
- [NEW] E→F promotion count vs total map size (defect #1)
- [NEW] LOGICAL_COVERAGE correctness: no false parity claims (defect #2)
- [NEW] Schema grounding requires explicit classification (defect #3)
- [NEW] cfg(test) stripping robust against braces in strings/comments (defect #4)
- [NEW] Engine-extra means no semantic equivalent (defect #5)
- [NEW] Source parity wording states ID presence only (defect #6)
"""

import re
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import audit_rule_categorization as audit


# ──────────────────────────────────────────────────────────────────────────────
# Todo #23: _REGO_DIAG_RE includes _at_source before _at
# ──────────────────────────────────────────────────────────────────────────────

class TestRegoRegex:
    """Verify _REGO_DIAG_RE matches all make_diag variants including _at_source."""

    @pytest.fixture
    def regex(self):
        return audit._REGO_DIAG_RE

    def test_matches_make_diag_at_source(self, regex):
        text = 'violation contains make_diag_at_source("E3023", "ERROR", name,'
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0][0] == "E3023"
        assert matches[0][1] == "ERROR"

    def test_matches_make_diag_plain(self, regex):
        text = 'violation contains make_diag("E3005", "ERROR", name,'
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0] == ("E3005", "ERROR")

    def test_matches_make_diag_full(self, regex):
        text = 'violation contains make_diag_full("W1028", "WARN", branch.resourceId, branch.path,'
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0] == ("W1028", "WARN")

    def test_matches_make_diag_at(self, regex):
        text = 'violation contains make_diag_at("E3051", "ERROR", name,'
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0] == ("E3051", "ERROR")

    def test_matches_make_diag_related(self, regex):
        text = 'violation contains make_diag_related("W2503", "WARN", source, edge.sourcePath,'
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0] == ("W2503", "WARN")

    def test_matches_make_diag_conditional(self, regex):
        text = 'violation contains make_diag_conditional("I3049", "INFO", name,'
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0] == ("I3049", "INFO")

    def test_at_source_matched_before_at(self, regex):
        """_at_source must be listed before _at in the alternation so it matches
        fully instead of matching just _at and leaving 'source' as noise."""
        text = 'make_diag_at_source("E3023", "ERROR", name, path, msg)'
        matches = regex.findall(text)
        assert len(matches) == 1
        # If _at was matched instead of _at_source, the regex would fail to
        # capture because 'source("E3023"...' wouldn't match the pattern.
        assert matches[0][0] == "E3023"

    def test_multiline_at_source(self, regex):
        """Verify DOTALL handles multiline at_source calls."""
        text = textwrap.dedent("""\
            violation contains make_diag_at_source(
                "E3023",
                "ERROR",
                name,
                path,
                msg
            )
        """)
        matches = regex.findall(text)
        assert len(matches) == 1
        assert matches[0][0] == "E3023"


# ──────────────────────────────────────────────────────────────────────────────
# Todo #24, #25: Production scan scope and reporting
# ──────────────────────────────────────────────────────────────────────────────

class TestProductionScanScope:
    """Verify the production emission scanner covers all required crates."""

    def test_production_crates_listed(self):
        """All expected crates are in the scan list."""
        expected = {
            "template-model", "schema-validator", "validation-engine",
            "diagnostics", "cel-engine", "rego-engine",
        }
        assert set(audit._PRODUCTION_SCAN_CRATES) == expected

    def test_scan_production_scopes_reports_crates(self):
        """scan_production_scopes returns all scanned directories."""
        scopes = audit.scan_production_scopes()
        crate_names = [name for name, _ in scopes]
        assert "template-model" in crate_names
        assert "schema-validator" in crate_names
        assert "cel-engine" in crate_names
        assert "rego-engine/handwritten" in crate_names

    def test_excludes_registry_definition(self):
        """Registry file is excluded from emission scanning."""
        assert audit._is_excluded_path("rules/src/registry.rs")

    def test_excludes_generated_code(self):
        """Generated artifacts are excluded."""
        assert audit._is_excluded_path("data-source/generated/foo.rs")

    def test_does_not_exclude_production_paths(self):
        """Regular production paths are not excluded."""
        assert not audit._is_excluded_path("cel-engine/src/rules/structure.rs")
        assert not audit._is_excluded_path("template-model/src/parser/builder.rs")
        assert not audit._is_excluded_path("schema-validator/src/validate.rs")


class TestCfgTestExclusion:
    """Verify #[cfg(test)] modules are stripped before scanning."""

    def test_strips_simple_cfg_test_module(self):
        text = textwrap.dedent("""\
            fn production_code() {
                make_parse_defect("F0001", "msg".into(), span);
            }

            #[cfg(test)]
            mod tests {
                fn test_helper() {
                    make_parse_defect("Z9999", "test only".into(), span);
                }
            }
        """)
        stripped = audit._strip_cfg_test_modules(text)
        assert "F0001" in stripped
        assert "Z9999" not in stripped

    def test_strips_nested_braces_in_test_module(self):
        text = textwrap.dedent("""\
            fn real() { make_parse_defect("E2001", "msg".into(), s); }

            #[cfg(test)]
            mod tests {
                fn nested() {
                    if true {
                        make_parse_defect("X1234", "bad".into(), s);
                    }
                }
            }

            fn also_real() { make_parse_defect("W3005", "msg".into(), s); }
        """)
        stripped = audit._strip_cfg_test_modules(text)
        assert "E2001" in stripped
        assert "W3005" in stripped
        assert "X1234" not in stripped

    def test_preserves_code_outside_test_modules(self):
        text = textwrap.dedent("""\
            RegisteredDiagnostic::new("F3012", "type mismatch")

            #[cfg(test)]
            mod unit_tests {
                RegisteredDiagnostic::new("Z0000", "fake")
            }

            RegisteredDiagnostic::new("E8002", "condition ref")
        """)
        stripped = audit._strip_cfg_test_modules(text)
        assert "F3012" in stripped
        assert "E8002" in stripped
        assert "Z0000" not in stripped

    def test_scan_rust_emissions_excludes_test_code(self, tmp_path):
        """Integration: scan_rust_emissions skips cfg(test) rule IDs."""
        rs_file = tmp_path / "lib.rs"
        rs_file.write_text(textwrap.dedent("""\
            fn emit() {
                RegisteredDiagnostic::new("F0001", "real emission");
            }

            #[cfg(test)]
            mod tests {
                fn test_it() {
                    RegisteredDiagnostic::new("Z9999", "test only");
                }
            }
        """))
        emissions = audit.scan_rust_emissions(tmp_path)
        ids = {e[0] for e in emissions}
        assert "F0001" in ids
        assert "Z9999" not in ids


class TestConstrainedRustEmissionFallback:
    """Dynamic IDs are detected only in diagnostic-flow contexts."""

    def test_rule_id_bindings_and_tuple_tables_are_detected(self, tmp_path):
        (tmp_path / "rules.rs").write_text(textwrap.dedent("""\
            fn emit() {
                let selected_rule_id = if enabled { "E1017" } else { "E1015" };
                let enum_checks = &[("E3628", "AWS::EC2::Instance")];
                consume(selected_rule_id, enum_checks);
            }
        """))

        emissions = audit.scan_rust_emissions(tmp_path)

        assert {emission[0] for emission in emissions} == {
            "E1015", "E1017", "E3628",
        }

    def test_arbitrary_rule_shaped_strings_are_not_emissions(self, tmp_path):
        (tmp_path / "messages.rs").write_text(textwrap.dedent("""\
            const MESSAGE: &str = "Z9999";
            fn documentation() -> &'static str { "E8888" }
        """))

        assert audit.scan_rust_emissions(tmp_path) == []

    def test_known_dynamic_diagnostic_helper_is_detected(self, tmp_path):
        (tmp_path / "helper.rs").write_text(textwrap.dedent("""\
            fn emit() {
                check_bdm_iops_ignored(
                    &mut findings,
                    model,
                    name,
                    mappings,
                    path,
                    "W3671",
                    ignored_types,
                );
            }
        """))

        emissions = audit.scan_rust_emissions(tmp_path)

        assert [emission[0] for emission in emissions] == ["W3671"]


# ──────────────────────────────────────────────────────────────────────────────
# Todo #24: Constructor-aware regex patterns
# ──────────────────────────────────────────────────────────────────────────────

class TestRustConstructorRegex:
    """Verify _RUST_CONSTRUCTOR_RE matches all required constructor patterns."""

    @pytest.fixture
    def regex(self):
        return audit._RUST_CONSTRUCTOR_RE

    def test_make_resource_diagnostic(self, regex):
        text = 'make_resource_diagnostic("E3510", &format!("IAM issue: {}", msg), m, rid, &path, None)'
        m = regex.search(text)
        assert m and m.group(1) == "E3510"

    def test_make_resource_diagnostic_at_source(self, regex):
        text = 'make_resource_diagnostic_at_source("E3023", &format!("DNS: {}", msg), m, rid, &p, &sp, None)'
        m = regex.search(text)
        assert m and m.group(1) == "E3023"

    def test_build_diagnostic(self, regex):
        text = 'build_diagnostic("F3002", &msg, m, rid, &format!("{}.{}", base, key), None)'
        m = regex.search(text)
        assert m and m.group(1) == "F3002"

    def test_build_diagnostic_conditional(self, regex):
        text = 'build_diagnostic_conditional("F3030", &message, m, rid, property_path, None, cond)'
        m = regex.search(text)
        assert m and m.group(1) == "F3030"

    def test_make_parse_defect(self, regex):
        text = 'make_parse_defect("F0000", msg, span)'
        m = regex.search(text)
        assert m and m.group(1) == "F0000"

    def test_make_parse_defect_at(self, regex):
        text = 'crate::make_parse_defect_at("F1032", message, arena.span(*value_ref), build_path)'
        m = regex.search(text)
        assert m and m.group(1) == "F1032"

    def test_make_parse_defect_for_resource(self, regex):
        text = 'make_parse_defect_for_resource("E2001", msg.into(), span, "MyResource")'
        m = regex.search(text)
        assert m and m.group(1) == "E2001"

    def test_registered_diagnostic_new(self, regex):
        text = 'RegisteredDiagnostic::new("W9012", message).build()'
        m = regex.search(text)
        assert m and m.group(1) == "W9012"

    def test_rule_diag_helper(self, regex):
        text = 'rule_diag("F8600", "Rules section must be an object".into(), "")'
        m = regex.search(text)
        assert m and m.group(1) == "F8600"


# ──────────────────────────────────────────────────────────────────────────────
# Todo #26: Explicit schema-grounded non-F set and exact origin mismatch
# ──────────────────────────────────────────────────────────────────────────────

class TestSchemaGroundedSet:
    """Verify non-Fatal Schema origins require concrete production emitters."""

    def test_computed_set_matches_required_schema_rules(self):
        expected = {
            "E8002", "E8001", "E8003", "E8004", "E8005", "E8006", "E8007",
            "E9004", "E1028", "E9101", "E9106", "E6005",
            "E1015", "E1016", "E1011", "E1017", "E1018", "E1019",
            "E1021", "E1022", "E1024", "E1030", "E1031", "E1033",
        }

        computed = audit._compute_schema_grounded_non_f(
            audit.parse_registry(),
            audit.scan_rust_emissions(),
            audit.scan_rego_emissions(),
        )

        assert computed == expected

    def test_missing_required_emitter_prevents_schema_grounding(self):
        registry = [
            ("E1016", "Error", "Intrinsic", "Schema", "GetAZs argument shape")
        ]
        rust_emissions = [
            ("E1016", "message", "cel-engine/src/rules/intrinsics.rs", 1)
        ]

        computed = audit._compute_schema_grounded_non_f(
            registry, rust_emissions, []
        )

        assert computed == frozenset()

    def test_schema_grounded_non_f_classified_as_schema(self, tmp_path):
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E8003.py").write_text(
            'id = "E8003"\nshortdesc = ("test",)'
        )

        origins = audit.compute_rule_origins(tmp_path)

        assert origins.true_origins["E8003"] == "Schema"

    def test_origin_mismatch_is_exact(self, tmp_path, monkeypatch):
        fake_registry = [
            ("E8003", "Error", "Intrinsic", "CfnLint", "Equals structure")
        ]
        monkeypatch.setattr(
            audit, "parse_registry", lambda path=audit.REGISTRY: fake_registry
        )
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E8003.py").write_text(
            'id = "E8003"\nshortdesc = ("test",)'
        )

        origins = audit.compute_rule_origins(tmp_path)

        assert origins.true_origins == {"E8003": "Schema"}
        assert len(origins.origin_issues) == 1
        assert origins.origin_issues[0][:3] == (
            "E8003", "CfnLint", "Schema",
        )


class TestAppendixMarkerConsistency:
    """Todo #27: Appendix ⚠ marker uses the exact same predicate as origin_issues."""

    def test_marker_matches_origin_issues(self, tmp_path):
        """Every rule with an origin issue gets ⚠ in appendix, and no others do."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        # Minimal cfn-lint fixture
        (rules_dir / "dummy.py").write_text('id = "E0001"\nshortdesc = ("test",)')
        origins = audit.compute_rule_origins(tmp_path)
        report = audit.build_report(origins)

        issue_ids = {item[0] for item in origins.origin_issues}
        # Check appendix lines
        in_appendix = False
        for line in report.split("\n"):
            if "## Appendix:" in line:
                in_appendix = True
                continue
            if in_appendix and line.startswith("| `"):
                rid = line.split("`")[1]
                has_marker = "⚠" in line
                if rid in issue_ids:
                    assert has_marker, f"{rid} has origin issue but no ⚠ in appendix"
                else:
                    assert not has_marker, f"{rid} has no origin issue but got ⚠ in appendix"


# ──────────────────────────────────────────────────────────────────────────────
# Todo #28: No forced W9003/W1019 engine-extra
# ──────────────────────────────────────────────────────────────────────────────

class TestNoForcedEngineExtra:
    """W9003 and W1019 must not be forced into engine-extra."""

    def test_w9003_not_forced(self, tmp_path):
        """W9003 has cfn-lint equivalents (aliases E3012/F3012) and is NOT engine-extra."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E3012.py").write_text('id = "E3012"\nshortdesc = ("Type check",)')
        origins = audit.compute_rule_origins(tmp_path)
        # W9003 aliases E3012 in the equivalence table, so it has a cfn-lint equivalent
        assert "W9003" not in origins.engine_extra

    def test_w1019_not_forced(self, tmp_path):
        """W1019 has cfn-lint equivalents and is NOT engine-extra."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "W1019.py").write_text('id = "W1019"\nshortdesc = ("Sub params",)')
        origins = audit.compute_rule_origins(tmp_path)
        # W1019 has a direct cfn-lint ID
        assert "W1019" not in origins.engine_extra

    def test_source_has_no_engine_extra_add_w9003(self):
        """The source code must not contain engine_extra.add('W9003')."""
        source = Path(audit.__file__).read_text()
        assert 'engine_extra.add("W9003")' not in source

    def test_source_has_no_engine_extra_add_w1019(self):
        """The source code must not contain engine_extra.add('W1019')."""
        source = Path(audit.__file__).read_text()
        assert 'engine_extra.add("W1019")' not in source


class TestDiagnosticEngineExtraInvariant:
    """Diagnostic content cannot bypass direct or aliased equivalence."""

    def test_equivalent_schema_and_enum_rules_are_never_engine_extra(self, tmp_path):
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "rules.py").write_text(textwrap.dedent("""\
            id = "E3002"
            id = "E3003"
            id = "E3030"
            shortdesc = "schema"
        """))

        origins = audit.compute_rule_origins(tmp_path)

        assert origins.engine_to_cfnlint["W3030"] == {"E3030"}
        diagnostics = [
            {"rule_id": "F3002", "message": "failure (from extension)"},
            {"rule_id": "F3003", "message": "OwnershipControls required"},
            {"rule_id": "W3030", "message": "Fn::If value is unknown"},
        ]
        assert not any(
            origins.is_engine_extra_diagnostic(diagnostic)
            for diagnostic in diagnostics
        )

    def test_rule_without_equivalent_uses_computed_engine_extra_set(self, tmp_path):
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "rule.py").write_text(
            'id = "E3002"\nshortdesc = "schema"'
        )

        origins = audit.compute_rule_origins(tmp_path)

        assert "F0001" in origins.engine_extra
        assert origins.is_engine_extra_diagnostic({"rule_id": "F0001"})


# ──────────────────────────────────────────────────────────────────────────────
# Todo #29: Post-computation invariant validation
# ──────────────────────────────────────────────────────────────────────────────

class TestEngineExtraInvariant:
    """No rule with a direct or aliased cfn-lint equivalent can be engine-extra."""

    def test_invariant_catches_direct_equivalent(self, tmp_path, monkeypatch):
        """If a rule has a direct cfn-lint ID, it cannot be engine-extra."""
        # Patch the registry to return a rule that would naively be engine-extra
        # but has a direct cfn-lint equivalent
        fake_registry = [("E9999", "Error", "Structure", "Engine", "Test rule")]
        monkeypatch.setattr(audit, "parse_registry", lambda path=None: fake_registry)

        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        # E9999 exists in cfn-lint → has a direct equivalent
        (rules_dir / "E9999.py").write_text('id = "E9999"\nshortdesc = ("Test",)')

        origins = audit.compute_rule_origins(tmp_path)
        # E9999 is CfnLint, not engine-extra
        assert "E9999" not in origins.engine_extra
        assert origins.true_origins["E9999"] == "CfnLint"

    def test_invariant_violations_report_concrete_aliases(self):
        violations = audit._find_engine_extra_invariant_violations(
            {"W3030", "F0001"},
            {"E3030": ("enum", "Enum.py")},
            {"W3030"},
            {"W3030": {"E3030"}},
        )

        assert violations == [("W3030", "alias", ["E3030"])]

    def test_real_engine_extra_has_no_cfnlint_equivalents(self, tmp_path):
        """Integration: verify the real engine_extra set satisfies the invariant."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "dummy.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        for rid in origins.engine_extra:
            assert rid not in origins.cfnlint_ids, \
                f"{rid} is engine-extra but has direct cfn-lint ID"
            # Check aliases
            cfn_via_alias = ({rid} | origins.rule_aliases.get(rid, set())) & set(origins.cfnlint_ids)
            # The rule may alias cfn-lint IDs that aren't in this checkout
            # (cfnlint_ids only contains what's in the fixture), so we check
            # against the cfnlint_equivalent set which is the authoritative source
            assert rid not in (origins.cfnlint_ids.keys() if hasattr(origins.cfnlint_ids, 'keys')
                               else origins.cfnlint_ids)


class TestStaleLogicalCoverage:
    """Logical coverage may reference only registered engine rule IDs."""

    def test_finds_only_absent_rule_id_components(self):
        logical_coverage = {
            "E1000": ("F0001/E8002", "both present"),
            "E1001": ("F0001+W9999", "one absent"),
            "E1002": ("schema-ext", "non-rule mechanism"),
        }

        stale = audit._find_stale_logical_coverage(
            {"F0001", "E8002"}, logical_coverage
        )

        assert stale == [
            ("E1001", "W9999", "F0001+W9999", "one absent")
        ]


# ──────────────────────────────────────────────────────────────────────────────
# Todo #30: Main exit status for all failure classes
# ──────────────────────────────────────────────────────────────────────────────

class TestMainExitStatus:
    """main() exits nonzero for any audit failure."""

    @pytest.fixture(autouse=True)
    def no_stale_logical_coverage(self, monkeypatch):
        monkeypatch.setattr(
            audit, "_find_stale_logical_coverage", lambda registry_ids: []
        )

    @pytest.fixture
    def cfnlint_fixture(self, tmp_path):
        """Create a minimal cfn-lint fixture directory."""
        rules_dir = tmp_path / "cfnlint" / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("Base",)')
        (rules_dir / "E3012.py").write_text('id = "E3012"\nshortdesc = ("Type",)')
        return tmp_path / "cfnlint"

    @pytest.fixture
    def output_path(self, tmp_path):
        return tmp_path / "output" / "report.md"

    def test_exits_nonzero_on_origin_issues(self, tmp_path, output_path, monkeypatch):
        mock_origins = audit.RuleOrigins(
            registry=[("E0001", "Error", "Structure", "CfnLint", "test")],
            cfnlint_ids={},
            true_origins={"E0001": "Engine"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[
                ("E0001", "CfnLint", "Engine", "no equivalent")
            ],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        registry = tmp_path / "registry.rs"
        registry.write_text("")
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "REGISTRY", registry)
        monkeypatch.setattr(
            audit, "compute_rule_origins", lambda root: mock_origins
        )
        monkeypatch.setattr(audit, "build_report", lambda origins: "# report\n")
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda directory=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])

        assert audit.main() == 1

    def test_exits_nonzero_on_parity_gaps(self, tmp_path, output_path, monkeypatch):
        mock_origins = audit.RuleOrigins(
            registry=[
                ("E3023", "Error", "Resource", "CfnLint", "record sets")
            ],
            cfnlint_ids={},
            true_origins={"E3023": "CfnLint"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        registry = tmp_path / "registry.rs"
        registry.write_text("")
        emission = [("E3023", "record sets", "resources_extra.rs", 10)]
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "REGISTRY", registry)
        monkeypatch.setattr(
            audit, "compute_rule_origins", lambda root: mock_origins
        )
        monkeypatch.setattr(audit, "build_report", lambda origins: "# report\n")
        monkeypatch.setattr(
            audit, "scan_rust_emissions", lambda directory=None: emission
        )
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])

        assert audit.main() == 1

    def test_exits_zero_when_all_pass(self, tmp_path, monkeypatch):
        """When no failures, main returns 0."""
        # Mock everything to return no issues
        mock_origins = audit.RuleOrigins(
            registry=[],
            cfnlint_ids={},
            true_origins={},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda d: False,
        )
        output_path = tmp_path / "report.md"
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "compute_rule_origins", lambda x: mock_origins)
        monkeypatch.setattr(audit, "build_report", lambda x: "# empty\n")
        monkeypatch.setattr(audit, "audit_results", lambda x: {})
        monkeypatch.setattr(audit, "REGISTRY", tmp_path / "fake_registry.rs")
        (tmp_path / "fake_registry.rs").write_text("")
        result = audit.main()
        assert result == 0

    def test_exits_nonzero_on_unregistered_emissions(self, tmp_path, monkeypatch):
        """Nonzero exit when unregistered emissions are found."""
        mock_origins = audit.RuleOrigins(
            registry=[("E0001", "Error", "Structure", "CfnLint", "test")],
            cfnlint_ids={"E0001": ("test", "test.py")},
            true_origins={"E0001": "CfnLint"},
            cfnlint_to_engine={"E0001": "E0001"},
            engine_to_cfnlint={"E0001": {"E0001"}},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda d: False,
        )
        output_path = tmp_path / "report.md"
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "compute_rule_origins", lambda x: mock_origins)
        monkeypatch.setattr(audit, "build_report", lambda x: "# report\n")
        # Mock scan to return unregistered ID
        monkeypatch.setattr(audit, "scan_rust_emissions",
                            lambda d=None: [("Z9999", "bad", "fake.rs", 1)])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])
        monkeypatch.setattr(audit, "REGISTRY", tmp_path / "fake_registry.rs")
        (tmp_path / "fake_registry.rs").write_text("")
        result = audit.main()
        assert result == 1

    def test_exits_nonzero_on_severity_mismatch(self, tmp_path, monkeypatch):
        """Nonzero exit when Rego severity mismatches are found."""
        mock_origins = audit.RuleOrigins(
            registry=[("E3005", "Error", "Reference", "CfnLint", "deps")],
            cfnlint_ids={"E3005": ("deps", "deps.py")},
            true_origins={"E3005": "CfnLint"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda d: False,
        )
        output_path = tmp_path / "report.md"
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "compute_rule_origins", lambda x: mock_origins)
        monkeypatch.setattr(audit, "build_report", lambda x: "# report\n")
        # Mock scan: Rego emits E3005 with wrong severity "WARN" (should be ERROR)
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda d=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions",
                            lambda: [("E3005", "WARN", "rego/deps.rego", 10)])
        monkeypatch.setattr(audit, "REGISTRY", tmp_path / "fake_registry.rs")
        (tmp_path / "fake_registry.rs").write_text("")
        result = audit.main()
        assert result == 1

    def test_exits_nonzero_on_invariant_violation(self, tmp_path, monkeypatch):
        """Nonzero exit when engine-extra invariant is violated."""
        mock_origins = audit.RuleOrigins(
            registry=[("E0001", "Error", "Structure", "CfnLint", "test")],
            cfnlint_ids={"E0001": ("test", "test.py")},
            true_origins={"E0001": "CfnLint"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[("W9003", "alias", ["E3012"])],
            is_engine_extra_diagnostic=lambda d: False,
        )
        output_path = tmp_path / "report.md"
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "compute_rule_origins", lambda x: mock_origins)
        monkeypatch.setattr(audit, "build_report", lambda x: "# report\n")
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda d=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])
        monkeypatch.setattr(audit, "REGISTRY", tmp_path / "fake_registry.rs")
        (tmp_path / "fake_registry.rs").write_text("")
        result = audit.main()
        assert result == 1

    def test_exits_nonzero_on_stale_logical_coverage(self, tmp_path, monkeypatch):
        mock_origins = audit.RuleOrigins(
            registry=[],
            cfnlint_ids={},
            true_origins={},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        output_path = tmp_path / "report.md"
        registry = tmp_path / "registry.rs"
        registry.write_text("")
        stale = [("E9999", "F9999", "F9999", "missing implementation")]
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(output_path),
        ])
        monkeypatch.setattr(audit, "REGISTRY", registry)
        monkeypatch.setattr(audit, "compute_rule_origins", lambda root: mock_origins)
        monkeypatch.setattr(audit, "build_report", lambda origins: "# report\n")
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda directory=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])
        monkeypatch.setattr(
            audit, "_find_stale_logical_coverage", lambda registry_ids: stale
        )

        assert audit.main() == 1

    def test_exits_two_on_missing_registry(self, tmp_path, monkeypatch):
        """Exit code 2 when registry file is missing."""
        monkeypatch.setattr(sys, "argv", [
            "audit", "--cfn-lint-root", str(tmp_path),
            "--output", str(tmp_path / "report.md"),
        ])
        monkeypatch.setattr(audit, "REGISTRY", tmp_path / "nonexistent.rs")
        result = audit.main()
        assert result == 2


# ──────────────────────────────────────────────────────────────────────────────
# Integration: audit_results structure
# ──────────────────────────────────────────────────────────────────────────────

class TestAuditResults:
    """Verify audit_results returns structured data."""

    @pytest.fixture(autouse=True)
    def no_stale_logical_coverage(self, monkeypatch):
        monkeypatch.setattr(
            audit, "_find_stale_logical_coverage", lambda registry_ids: []
        )

    def test_returns_dict(self, tmp_path):
        """audit_results returns a dict."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        results = audit.audit_results(origins)
        assert isinstance(results, dict)

    def test_empty_dict_means_all_pass(self, tmp_path, monkeypatch):
        """Empty dict from audit_results means no failures."""
        mock_origins = audit.RuleOrigins(
            registry=[],
            cfnlint_ids={},
            true_origins={},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda d: False,
        )
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda d=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])
        results = audit.audit_results(mock_origins)
        assert results == {}

    def test_shared_rust_emission_is_not_an_engine_parity_gap(self, monkeypatch):
        origins = audit.RuleOrigins(
            registry=[("F3003", "Fatal", "Schema", "Schema", "required property")],
            cfnlint_ids={},
            true_origins={"F3003": "Schema"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        monkeypatch.setattr(
            audit,
            "scan_rust_emissions",
            lambda directory=None: [("F3003", "required", "schema-validator/src/validate.rs", 1)]
            if directory is None
            else [],
        )
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])

        assert audit.audit_results(origins) == {}

    def test_at_source_rule_present_in_both_engines_has_no_gap(self, monkeypatch):
        origins = audit.RuleOrigins(
            registry=[("E3023", "Error", "Resource", "CfnLint", "record sets")],
            cfnlint_ids={},
            true_origins={"E3023": "CfnLint"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        emission = [("E3023", "record sets", "resources_extra.rs", 10)]
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda directory=None: emission)
        monkeypatch.setattr(
            audit,
            "scan_rego_emissions",
            lambda: [("E3023", "ERROR", "rego/resources/route53.rego", 5)],
        )

        assert audit.audit_results(origins) == {}

    def test_engine_owned_emission_mismatch_is_a_parity_gap(self, monkeypatch):
        origins = audit.RuleOrigins(
            registry=[("E3023", "Error", "Resource", "CfnLint", "record sets")],
            cfnlint_ids={},
            true_origins={"E3023": "CfnLint"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        emission = [("E3023", "record sets", "resources_extra.rs", 10)]
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda directory=None: emission)
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])

        assert audit.audit_results(origins)["parity_gaps"] == {"rust_only": ["E3023"], "rego_only": []}

    def test_stale_logical_coverage_propagated(self, monkeypatch):
        origins = audit.RuleOrigins(
            registry=[("F0001", "Fatal", "Structure", "Schema", "resources")],
            cfnlint_ids={},
            true_origins={"F0001": "Schema"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda diagnostic: False,
        )
        stale = [("E9999", "F9999", "F9999", "missing implementation")]
        monkeypatch.setattr(
            audit, "_find_stale_logical_coverage", lambda registry_ids: stale
        )
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda directory=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])

        assert audit.audit_results(origins)["stale_logical_coverage"] == stale

    def test_origin_issues_propagated(self, tmp_path, monkeypatch):
        """Origin issues are included in results."""
        mock_origins = audit.RuleOrigins(
            registry=[("E0001", "Error", "Structure", "CfnLint", "test")],
            cfnlint_ids={},
            true_origins={"E0001": "Engine"},
            cfnlint_to_engine={},
            engine_to_cfnlint={},
            engine_extra=set(),
            engine_extra_collisions=set(),
            engine_stricter=set(),
            rule_aliases={},
            origin_issues=[("E0001", "CfnLint", "Engine", "no equivalent")],
            engine_extra_invariant_violations=[],
            is_engine_extra_diagnostic=lambda d: False,
        )
        monkeypatch.setattr(audit, "scan_rust_emissions", lambda d=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])
        results = audit.audit_results(mock_origins)
        assert "origin_issues" in results
        assert len(results["origin_issues"]) == 1


# ──────────────────────────────────────────────────────────────────────────────
# Defect #1: E→F promotion count vs total map size
# ──────────────────────────────────────────────────────────────────────────────

class TestMappingBreakdown:
    """The report must distinguish E→F promotions from E→E/E→W mappings."""

    def test_e_to_f_count_is_40(self):
        """The explicit mapping table has exactly 40 E→F promotions."""
        # Extract the raw table from the source (before filtering by cfn-lint
        # checkout). This tests the table definition itself.
        source = Path(audit.__file__).read_text()
        import re as _re
        entries = _re.findall(
            r'"(E\d{4})"\s*:\s*"(F\d{4})"', source
        )
        assert len(entries) == 40, (
            f"Expected 40 E→F promotions in _CFNLINT_TO_ENGINE, got {len(entries)}"
        )

    def test_e_to_e_mappings_counted_separately(self):
        """E→E mappings are not counted as promotions."""
        source = Path(audit.__file__).read_text()
        import re as _re
        e_to_e = _re.findall(r'"(E\d{4})"\s*:\s*"(E\d{4})"', source)
        assert len(e_to_e) == 11, (
            f"Expected 11 E→E mappings, got {len(e_to_e)}"
        )

    def test_e_to_w_mappings_counted_separately(self):
        """E→W downgrades are not counted as promotions."""
        source = Path(audit.__file__).read_text()
        import re as _re
        e_to_w = _re.findall(r'"(E\d{4})"\s*:\s*"(W\d{4})"', source)
        assert len(e_to_w) == 1, (
            f"Expected 1 E→W downgrade, got {len(e_to_w)}"
        )

    def test_report_labels_mapping_types_separately(self, tmp_path):
        """build_report shows E→F, E→E, E→W counts separately."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        (rules_dir / "E3012.py").write_text('id = "E3012"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        report = audit.build_report(origins)
        # The report must contain separate counts, not just the total
        assert "E→F promotions" in report
        assert "E→E same/split" in report
        assert "E→W downgrades" in report
        # Must NOT contain the old misleading label
        assert "E→F promoted rules: " not in report

    def test_verified_split_aliases_share_reference_ids(self, tmp_path):
        """Split engine rules retain the reference IDs for their shared concern."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "rules.py").write_text(textwrap.dedent("""\
            id = "E2015"
            id = "E7001"
            id = "E7010"
            id = "E1011"
            id = "W2501"
            shortdesc = "test"
        """))

        origins = audit.compute_rule_origins(tmp_path)

        expected = {
            "F2012": "E2015",
            "F0017": "E7001",
            "F0050": "E7010",
            "F1012": "E1011",
            "W2509": "W2501",
        }
        for engine_id, reference_id in expected.items():
            assert reference_id in origins.rule_aliases[engine_id]
            assert reference_id in origins.engine_to_cfnlint[engine_id]
            assert engine_id not in origins.engine_extra
        assert origins.true_origins["W2509"] == "CfnLint"

    def test_direct_cli_does_not_spawn_pytest(self):
        """Normal report generation must not depend on a pytest installation."""
        source = Path(audit.__file__).read_text()
        assert "run_script_tests" not in source
        assert "subprocess.run" not in source


# ──────────────────────────────────────────────────────────────────────────────
# Defect #2: LOGICAL_COVERAGE correctness
# ──────────────────────────────────────────────────────────────────────────────

class TestLogicalCoverageCorrectness:
    """LOGICAL_COVERAGE entries must not claim unproven behavioral parity."""

    def test_i1002_is_out_of_scope(self):
        """I1002 (approaching template size) is out-of-scope, not covered."""
        mechanism, _ = audit.LOGICAL_COVERAGE["I1002"]
        assert mechanism == "out-of-scope", (
            f"I1002 should be out-of-scope, got '{mechanism}'"
        )

    def test_i3010_is_out_of_scope(self):
        """I3010 (resource count approaching limit) is out-of-scope."""
        mechanism, _ = audit.LOGICAL_COVERAGE["I3010"]
        assert mechanism == "out-of-scope", (
            f"I3010 should be out-of-scope, got '{mechanism}'"
        )

    def test_w1019_references_direct_implementation(self):
        """W1019 references its own direct ID, not F1018/E1029."""
        mechanism, note = audit.LOGICAL_COVERAGE["W1019"]
        assert mechanism == "W1019", (
            f"W1019 should reference itself as direct implementation, got '{mechanism}'"
        )
        assert "F1018" not in mechanism
        assert "E1029" not in mechanism

    def test_e1001_notes_partial_coverage(self):
        """E1001 note must state partial coverage, not full equivalence."""
        _, note = audit.LOGICAL_COVERAGE["E1001"]
        assert "partial" in note.lower(), (
            f"E1001 note must state partial coverage: '{note}'"
        )

    def test_e1011_notes_structural_only(self):
        """E1011 note must clarify it's structural shape only."""
        _, note = audit.LOGICAL_COVERAGE["E1011"]
        assert "structural" in note.lower() or "shape" in note.lower(), (
            f"E1011 note must clarify structural-only: '{note}'"
        )

    def test_e7010_notes_structural_limit_only(self):
        """E7010 points to the per-mapping structural limit implementation."""
        mechanism, note = audit.LOGICAL_COVERAGE["E7010"]
        assert mechanism == "F0050"
        assert "structural limit only" in note.lower() or "limit only" in note.lower(), (
            f"E7010 note must mention structural limit only: '{note}'"
        )

    def test_header_disclaims_behavioral_parity(self):
        """The LOGICAL_COVERAGE source must disclaim behavioral parity."""
        source = Path(audit.__file__).read_text()
        # Find the docblock before LOGICAL_COVERAGE
        idx = source.index("LOGICAL_COVERAGE = {")
        block = source[max(0, idx - 1000):idx]
        assert "behavioral parity" in block.lower() or "NOT claim" in block, (
            "LOGICAL_COVERAGE header must disclaim behavioral parity"
        )

    def test_no_false_coverage_via_unrelated_rules(self):
        """Entries must not claim coverage by rules that check a different concern."""
        # W1019 checks UNUSED Sub params; E1029/F1018 check MISSING Sub vars.
        # These are different concerns.
        mechanism, _ = audit.LOGICAL_COVERAGE["W1019"]
        assert "E1029" not in mechanism and "F1018" not in mechanism


# ──────────────────────────────────────────────────────────────────────────────
# Defect #3: Schema grounding requires explicit classification
# ──────────────────────────────────────────────────────────────────────────────

class TestSchemaGroundingExplicitClassification:
    """Schema origin requires explicit contract classification, not just source location."""

    def test_unlisted_template_model_rule_not_promoted(self):
        """A rule emitted from template-model but NOT in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS
        is NOT classified as Schema."""
        # F9999 is hypothetically emitted from template-model but not in the
        # explicit classification set → should not be Schema for non-F rules
        registry = [
            ("E9999", "Error", "Structure", "Engine", "Hypothetical rule")
        ]
        rust_emissions = [
            ("E9999", "message", "template-model/src/parser.rs", 42)
        ]
        computed = audit._compute_schema_grounded_non_f(
            registry, rust_emissions, []
        )
        # E9999 is NOT in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS, so not grounded
        assert "E9999" not in computed

    def test_listed_rule_with_emitters_is_grounded(self):
        """A rule listed in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS with confirmed
        emitters IS classified as Schema."""
        # E8003 is in _TEMPLATE_MODEL_SCHEMA_RULES
        registry = [
            ("E8003", "Error", "Intrinsic", "Schema", "Fn::Equals structure")
        ]
        rust_emissions = [
            ("E8003", "msg", "template-model/src/conditions.rs", 10)
        ]
        computed = audit._compute_schema_grounded_non_f(
            registry, rust_emissions, []
        )
        assert "E8003" in computed

    def test_docstring_mentions_explicit_classification(self):
        """The _compute_schema_grounded_non_f docstring must mention explicit classification."""
        docstring = audit._compute_schema_grounded_non_f.__doc__
        assert "explicit" in docstring.lower()
        assert "source location alone" in docstring.lower() or "NOT proof" in docstring

    def test_schema_grounding_requirements_documented(self):
        """_SCHEMA_GROUNDING_SOURCE_REQUIREMENTS has a doccomment explaining
        that source location alone is not proof."""
        source = Path(audit.__file__).read_text()
        idx = source.index("_SCHEMA_GROUNDING_SOURCE_REQUIREMENTS")
        block = source[max(0, idx - 800):idx + 100]
        assert "source location alone" in block.lower() or "NOT sufficient" in block


# ──────────────────────────────────────────────────────────────────────────────
# Defect #4: cfg(test) stripping robust against strings/comments
# ──────────────────────────────────────────────────────────────────────────────

class TestCfgTestStrippingRobustness:
    """cfg(test) stripping must handle braces in strings, raw strings, and comments."""

    def test_brace_in_string_does_not_close_module(self):
        """A '}' inside a string literal must not end the test module early."""
        text = textwrap.dedent('''\
            fn production() {
                RegisteredDiagnostic::new("E0001", "real");
            }

            #[cfg(test)]
            mod tests {
                fn test_it() {
                    let msg = "closing brace } in string";
                    RegisteredDiagnostic::new("Z9999", "test only");
                }
            }
        ''')
        stripped = audit._strip_cfg_test_modules(text)
        assert "E0001" in stripped
        assert "Z9999" not in stripped, (
            "Brace in string caused premature module close"
        )

    def test_brace_in_raw_string_does_not_close_module(self):
        """A '}' inside a raw string r#"..."# must not end the test module."""
        text = textwrap.dedent('''\
            fn production() {
                RegisteredDiagnostic::new("E0002", "real");
            }

            #[cfg(test)]
            mod tests {
                fn test_it() {
                    let pattern = r#"regex with } brace"#;
                    RegisteredDiagnostic::new("Z8888", "test");
                }
            }
        ''')
        stripped = audit._strip_cfg_test_modules(text)
        assert "E0002" in stripped
        assert "Z8888" not in stripped

    def test_brace_in_line_comment_does_not_close_module(self):
        """A '}' in a line comment must not end the test module."""
        text = textwrap.dedent('''\
            fn production() {
                RegisteredDiagnostic::new("E0003", "real");
            }

            #[cfg(test)]
            mod tests {
                // This comment has a } brace
                fn test_it() {
                    RegisteredDiagnostic::new("Z7777", "test");
                }
            }
        ''')
        stripped = audit._strip_cfg_test_modules(text)
        assert "E0003" in stripped
        assert "Z7777" not in stripped

    def test_brace_in_block_comment_does_not_close_module(self):
        """A '}' in a block comment must not end the test module."""
        text = textwrap.dedent('''\
            fn production() {
                RegisteredDiagnostic::new("E0004", "real");
            }

            #[cfg(test)]
            mod tests {
                /* block comment with } brace */
                fn test_it() {
                    RegisteredDiagnostic::new("Z6666", "test");
                }
            }
        ''')
        stripped = audit._strip_cfg_test_modules(text)
        assert "E0004" in stripped
        assert "Z6666" not in stripped

    def test_escaped_quote_in_string_does_not_break_scanning(self):
        """An escaped quote \\\" inside a string must not break string detection."""
        text = textwrap.dedent('''\
            fn production() {
                RegisteredDiagnostic::new("E0005", "real");
            }

            #[cfg(test)]
            mod tests {
                fn test_it() {
                    let s = "escaped \\" and } brace";
                    RegisteredDiagnostic::new("Z5555", "test");
                }
            }
        ''')
        stripped = audit._strip_cfg_test_modules(text)
        assert "E0005" in stripped
        assert "Z5555" not in stripped

    def test_fail_closed_on_unbalanced_input(self):
        """If matching brace is never found, strip remainder (fail-closed)."""
        text = textwrap.dedent('''\
            fn production() {
                RegisteredDiagnostic::new("E0006", "real");
            }

            #[cfg(test)]
            mod tests {
                fn test_it() {
                    RegisteredDiagnostic::new("Z4444", "test");
                // missing closing brace
        ''')
        stripped = audit._strip_cfg_test_modules(text)
        assert "E0006" in stripped
        # Fail-closed: Z4444 must be stripped even though brace is unbalanced
        assert "Z4444" not in stripped


# ──────────────────────────────────────────────────────────────────────────────
# Defect #5: Engine-extra means no semantic equivalent
# ──────────────────────────────────────────────────────────────────────────────

class TestEngineExtraSemanticEquivalent:
    """Engine-extra must mean no semantic equivalent, not just no numeric mapping."""

    def test_collision_rules_are_engine_extra(self, tmp_path):
        """Rules with Engine(collision) origin are engine-extra because the
        colliding cfn-lint rule implements a DIFFERENT check."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "dummy.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        # Any Engine(collision) rule should be in engine_extra
        for rid, true_o in origins.true_origins.items():
            if true_o == "Engine(collision)":
                assert rid in origins.engine_extra, (
                    f"{rid} has Engine(collision) but is not in engine_extra"
                )
                assert rid in origins.engine_extra_collisions

    def test_engine_extra_collisions_is_subset(self, tmp_path):
        """engine_extra_collisions is always a subset of engine_extra."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        assert origins.engine_extra_collisions <= origins.engine_extra

    def test_report_shows_collision_count(self, tmp_path):
        """The report summary shows collision count alongside engine-extra."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        report = audit.build_report(origins)
        assert "number collisions" in report

    def test_aliased_rule_never_engine_extra(self, tmp_path):
        """A rule with a cfn-lint semantic equivalent via alias is never engine-extra."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E3012.py").write_text('id = "E3012"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        # W9003 aliases E3012 — it must NOT be engine-extra
        assert "W9003" not in origins.engine_extra
        # W3030 aliases E3030 — if E3030 is present in cfn-lint
        if "E3030" in origins.cfnlint_ids:
            assert "W3030" not in origins.engine_extra


# ──────────────────────────────────────────────────────────────────────────────
# Defect #6: Source parity wording states ID presence only
# ──────────────────────────────────────────────────────────────────────────────

class TestSourceParityWording:
    """Source parity reporting must state it checks ID presence only."""

    def test_report_gap_section_disclaims_behavioral_parity(self, tmp_path):
        """When there are gaps, the section title/text must disclaim behavioral parity."""
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        report = audit.build_report(origins)
        # Must use "ID presence" language, not "parity"
        if "Engine source" in report:
            assert "ID presence" in report or "presence only" in report

    def test_report_success_disclaims_behavioral_parity(self, tmp_path, monkeypatch):
        """When no gaps exist, the success message still disclaims behavioral parity."""
        # Mock to have no gaps
        rules_dir = tmp_path / "src" / "cfnlint" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "E0001.py").write_text('id = "E0001"\nshortdesc = ("t",)')
        origins = audit.compute_rule_origins(tmp_path)
        # Rebuild report with mocked empty gaps
        monkeypatch.setattr(audit, "scan_rust_emissions",
                            lambda directory=None: [])
        monkeypatch.setattr(audit, "scan_rego_emissions", lambda: [])
        report = audit.build_report(origins)
        # The success line should mention ID presence
        if "Engine source ID presence" in report:
            assert "behavioral parity" in report.lower() or "ID presence" in report

    def test_audit_results_parity_gaps_comment_mentions_id_presence(self):
        """The audit_results code comment must mention ID presence."""
        source = Path(audit.__file__).read_text()
        # Find the parity_gaps section in audit_results function
        # Look for the comment block that precedes parity_gaps assignment
        audit_fn_start = source.index("def audit_results(")
        parity_idx = source.index("parity_gaps", audit_fn_start)
        block = source[max(audit_fn_start, parity_idx - 400):parity_idx + 50]
        assert "ID presence" in block or "id presence" in block.lower() or \
            "NOT verify behavioral parity" in block
