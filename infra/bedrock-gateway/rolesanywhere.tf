# =============================================================================
# IAM Roles Anywhere — DGX On-Prem Gateway Access
# =============================================================================
# Trust Anchor + Profile for X.509 certificate-based authentication
# from on-premises DGX servers. Gated by var.enable_dgx_onprem_access.

resource "aws_rolesanywhere_trust_anchor" "dgx" {
  count   = var.enable_dgx_onprem_access ? 1 : 0
  name    = "${local.prefix}-dgx-trust-anchor"
  enabled = true

  source {
    source_type = "CERTIFICATE_BUNDLE"
    source_data {
      x509_certificate_data = var.dgx_ca_certificate_pem
    }
  }

  tags = {
    Service   = "bedrock-access-gateway"
    Component = "dgx-onprem"
    Env       = var.environment
  }

  # Guard against the 2026-08-14 failure mode recurring.
  #
  # `count` is driven by var.enable_dgx_onprem_access. If that flag is ever
  # false again (a var-file missing the key, a `-var` override), count goes to 0
  # and this Trust Anchor — plus the Profile below — is destroyed. Recreating it
  # mints a NEW Trust Anchor ARN, which no longer matches the aws:SourceArn
  # condition the DGX clients authenticate against, and the on-prem certificates
  # would have to be re-enrolled.
  #
  # prevent_destroy turns that into a plan-time error. Because the error aborts
  # the whole plan, it also blocks the same apply from stripping the
  # rolesanywhere.amazonaws.com statement off the BedrockUser-* trust policies
  # (bedrock_users.tf renders it under the same flag) — which is what actually
  # broke DGX access. Both resources must be in state for this to fire; they are.
  #
  # Tearing DGX access down on purpose means deleting this block first, on
  # purpose. In-place changes (CA rotation, tags) are unaffected.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_rolesanywhere_profile" "dgx" {
  count   = var.enable_dgx_onprem_access ? 1 : 0
  name    = "${local.prefix}-dgx-profile"
  enabled = true

  role_arns = [
    for user in var.dgx_pilot_users :
    "arn:aws:iam::123456789012:role/BedrockUser-${user}"
  ]

  session_policy  = null
  duration_seconds = 3600

  depends_on = [aws_rolesanywhere_trust_anchor.dgx]

  tags = {
    Service   = "bedrock-access-gateway"
    Component = "dgx-onprem"
    Env       = var.environment
  }

  # See the Trust Anchor above. Same flag, same blast radius: this Profile was
  # already in state while the flag read false, so a plain apply was one step
  # away from deleting the Profile the DGX clients call.
  #
  # Note that role_arns is NOT protected by this — it tracks var.dgx_pilot_users,
  # so removing a name from that list still (correctly) removes their access.
  lifecycle {
    prevent_destroy = true
  }
}
