package structure

import rego.v1

# I3012: Logical ID approaching maximum length (256 characters)
violation contains make_diag("I3012", "INFO", name,
    sprintf("Logical ID '%s' is %d characters — approaching the 256 character limit", [name, count(name)])) if {
    some name, _ in input.resources
    count(name) > 200
}
