package zt

# Zero Trust policy for Open Banking requests.
# Input schema:
#   input.risk        float   [0,1]
#   input.telemetry   object  (device_fp_stable, geo_velocity, call_rate, ...)
#   input.checks      object  (token_valid, dpop_valid, jti_replayed, cnf_jkt_match)
#   input.thresholds  object  (allow: float, deny: float)

default decision := {"action": "DENY"}

# Hard rejects: any failed mandatory check triggers immediate DENY
deny_hard {
    input.checks.jti_replayed == true
}

deny_hard {
    input.checks.token_valid == false
}

deny_hard {
    input.checks.dpop_valid == false
    input.flags.enforce_dpop == true
}

# Sender-constraining is only a hard requirement while device binding is
# enforced; the §7.4 "P - device-binding" ablation turns it off in the
# controller, and the policy must follow or the ablation is a no-op.
deny_hard {
    input.checks.cnf_jkt_match == false
    input.flags.check_device_binding == true
}

# Risk-threshold decision
decision := {"action": "ALLOW"} {
    not deny_hard
    input.risk < input.thresholds.allow
}

decision := {"action": "CHALLENGE"} {
    not deny_hard
    input.risk >= input.thresholds.allow
    input.risk < input.thresholds.deny
}

decision := {"action": "DENY"} {
    deny_hard
}

decision := {"action": "DENY"} {
    not deny_hard
    input.risk >= input.thresholds.deny
}
