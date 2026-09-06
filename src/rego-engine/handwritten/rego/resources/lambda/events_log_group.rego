package resources

import rego.v1

# E2529: No more than 2 SubscriptionFilters per LogGroup (concrete string match)
violation contains make_diag_full("E2529", "ERROR", name,
    "Properties.LogGroupName",
    sprintf("CloudWatch Log Group has more than 2 subscription filters (found %d)", [count(filters)]),
    "Reduce the number of subscription filters to 2 or fewer per log group",
    "") if {
    cfn_rule_active("E2529")
    some name in resources_of_type("AWS::Logs::SubscriptionFilter")
    lgn := resolve(name, "Properties.LogGroupName")
    is_string(lgn)
    filters := {n |
        some n in resources_of_type("AWS::Logs::SubscriptionFilter")
        other_lgn := resolve(n, "Properties.LogGroupName")
        other_lgn == lgn
    }
    count(filters) > 2
    name == sort(filters)[0]
}

# E2529: No more than 2 SubscriptionFilters per LogGroup (Ref-based match)
violation contains make_diag_full("E2529", "ERROR", name,
    "Properties.LogGroupName",
    sprintf("CloudWatch Log Group has more than 2 subscription filters (found %d)", [count(filters)]),
    "Reduce the number of subscription filters to 2 or fewer per log group",
    "") if {
    cfn_rule_active("E2529")
    some name in resources_of_type("AWS::Logs::SubscriptionFilter")
    ref_target := follow_ref(name, "Properties.LogGroupName")
    ref_target != null
    filters := {n |
        some n in resources_of_type("AWS::Logs::SubscriptionFilter")
        other_ref := follow_ref(n, "Properties.LogGroupName")
        other_ref == ref_target
    }
    count(filters) > 2
    name == sort(filters)[0]
}
