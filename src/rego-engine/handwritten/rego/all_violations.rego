package all_violations

import rego.v1

violation contains v if { some v in data.structure.violation }
violation contains v if { some v in data.intrinsics.violation }
violation contains v if { some v in data.references.violation }
violation contains v if { some v in data.best_practices.violation }
violation contains v if { some v in data.resources.violation }
