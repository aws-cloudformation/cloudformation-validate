package cfnvalidate

import "runtime/debug"

const (
	developmentPackageVersion = "(devel)"
	goModulePath              = "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
)

// PackageVersion returns the Go module version embedded in the running binary.
// Tagged builds include the leading "v" and any prerelease suffix; local module
// replacements return "(devel)".
func PackageVersion() string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return developmentPackageVersion
	}

	if buildInfo.Main.Path == goModulePath {
		return resolvedModuleVersion(&buildInfo.Main)
	}
	for _, dependency := range buildInfo.Deps {
		if dependency.Path == goModulePath {
			return resolvedModuleVersion(dependency)
		}
	}
	return developmentPackageVersion
}

func resolvedModuleVersion(module *debug.Module) string {
	if module.Replace != nil {
		module = module.Replace
	}
	if module.Version == "" {
		return developmentPackageVersion
	}
	return module.Version
}
