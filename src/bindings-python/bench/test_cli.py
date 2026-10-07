"""Test CLI argument handling independent of the cloudformation_validate import."""
import subprocess
import sys
import os

BENCH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark.py")

def run(args):
    """Run benchmark.py with given args, capture exit code and stderr."""
    result = subprocess.run(
        [sys.executable, BENCH] + args,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr

def main():
    errors = []

    # --help should exit 0 and print usage
    code, out, err = run(["--help"])
    if code != 0:
        errors.append(f"--help exited {code}, expected 0")
    if "engine" not in (out + err).lower():
        errors.append("--help output missing 'engine' keyword")

    # Missing required --engine should fail
    code, out, err = run(["--iterations", "1"])
    if code == 0:
        errors.append("missing --engine should fail, got exit 0")

    # Missing required --iterations should fail
    code, out, err = run(["--engine", "rego"])
    if code == 0:
        errors.append("missing --iterations should fail, got exit 0")

    # Invalid engine choice should fail
    code, out, err = run(["--engine", "invalid", "--iterations", "1"])
    if code == 0:
        errors.append("invalid engine should fail, got exit 0")

    # Negative iterations should fail
    code, out, err = run(["--engine", "rego", "--iterations", "-1"])
    if code == 0:
        errors.append("negative iterations should fail, got exit 0")

    # Zero iterations should fail
    code, out, err = run(["--engine", "rego", "--iterations", "0"])
    if code == 0:
        errors.append("zero iterations should fail, got exit 0")

    # Rego rules cannot be loaded into the CEL engine
    code, out, err = run(["--engine", "cel", "--iterations", "1", "--rego-rules", "rules.rego"])
    if code == 0 or "--rego-rules" not in err:
        errors.append(f"--rego-rules with --engine cel should fail naming the flag, got exit {code}: {err.strip()}")

    # A scenario name is a single lowercase path component
    code, out, err = run(["--engine", "rego", "--iterations", "1", "--scenario", "Bad Name"])
    if code == 0 or "--scenario" not in err:
        errors.append(f"invalid --scenario should fail naming the flag, got exit {code}: {err.strip()}")

    # --guard-rules / --rego-rules require a value
    code, out, err = run(["--engine", "rego", "--iterations", "1", "--guard-rules"])
    if code == 0:
        errors.append("--guard-rules without a value should fail, got exit 0")

    if errors:
        print("FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("All CLI validation tests passed.")

if __name__ == "__main__":
    main()
