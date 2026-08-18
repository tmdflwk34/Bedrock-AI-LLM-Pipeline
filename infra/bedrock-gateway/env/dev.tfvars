environment                                = "dev"
aws_region                                 = "us-west-2"
ses_sender_email                           = "<SES_SENDER_EMAIL>"
ses_admin_group_email                      = "<ADMIN_EMAIL>"
discovery_mode                             = false
manage_api_gateway_account_cloudwatch_role = false
api_gateway_data_trace_enabled             = true
api_gateway_execution_logging_level        = "INFO"
private_subnet_ids         = ["<PRIVATE_SUBNET>", "<PRIVATE_SUBNET>"]
fargate_security_group_ids = ["<SECURITY_GROUP>"]

# Worker image pin (long-output-streaming 5.5, design.md U4).
#
# Unlike the previous pin — which recorded whatever `:latest` already pointed at
# and therefore changed nothing — this pair is the image **built from this
# repository state** for the task 7 deploy. Built and pushed as:
#
#   docker build --platform linux/amd64 -f worker/Dockerfile \
#     -t <repo>:lo-34a8c20 -t <repo>:latest worker/
#   docker push <repo>:lo-34a8c20 && docker push <repo>:latest
#
# Digest read back from the registry rather than from the push output:
#
#   AWS_PROFILE=bedrock-gw aws ecr describe-images \
#     --repository-name bedrock-gw-dev-worker --region us-west-2 \
#     --image-ids imageTag=lo-34a8c20
#
#   imageDigest        sha256:c3253ce3...52764eb3f  (OCI image index)
#   imageTags          ["lo-34a8c20", "latest"]
#   imagePushedAt      2026-08-14T08:30:08Z
#
# worker_source_commit is the commit that carries the worker source in that
# image (34a8c20, "raises single-generation ceiling 1800s -> 7200s"), so the
# `lo-<short sha>` tag, this pin, and the task definition's SourceCommit tag all
# name the same revision. Previous pin, for rollback:
#
#   worker_image_digest  = "sha256:13ee618e1fda44f199170028cdee996762c6d00ec85b67bf87374ec48fe2c90d"
#   worker_source_commit = "5066ac1e9312a41511becfb37bb7c61c420db7cd"
#
# **What this image DOES now contain**, and the previous one did not: the Phase 1
# worker changes — 4.1/4.2 remaining-budget arithmetic, 5.3 SIGTERM handler, 7.4
# mantle transport-timeout classification. The declared ceilings
# (PER_ATTEMPT_TIMEOUT_SECONDS=7200, WORKER_TOTAL_DEADLINE_SECONDS=7500) are
# read from the task definition by this image; the old one hard-coded 1800/2100
# and would ignore them.
worker_image_digest  = "sha256:c3253ce389005ccce6c5afc33ffb09ccf07d890e7b4168e91046dfa52764eb3f"
worker_source_commit = "34a8c20dc94437f9d693cb89df5fe7d4668dc4f0"

# =============================================================================
# DGX On-Prem Gateway Access (IAM Roles Anywhere)
# =============================================================================
# These three values MUST stay set. They are the recurrence fix for the
# 2026-08-14 outage (CreateSession 403 "Unable to assume role for
# BedrockUser-user08").
#
# What happened: the Roles Anywhere trust statement on the BedrockUser-* roles
# is rendered conditionally in bedrock_users.tf:
#
#   var.enable_dgx_onprem_access && contains(var.dgx_pilot_users, each.key)
#
# `enable_dgx_onprem_access` defaults to false and was never set here, so the
# apply at 2026-05-31T03:46:16Z (CloudTrail UpdateAssumeRolePolicy, Terraform
# 1.14.7 / provider 5.100.0) rewrote all 25 role trust policies WITHOUT the
# rolesanywhere.amazonaws.com principal. The Trust Anchor and Profile survived
# because they were created out-of-band, so DGX kept presenting a valid
# certificate to a role that no longer trusted Roles Anywhere. Last successful
# CreateSession: 2026-05-25T12:47:08Z. First denial after the apply:
# 2026-06-26T00:57:33Z.
#
# Leaving the flag false ALSO means `count = 0` on both rolesanywhere.tf
# resources, so a plain apply would destroy aws_rolesanywhere_profile.dgx[0]
# (it is in state) and break DGX again even after the trust policy is repaired.
enable_dgx_onprem_access = true

# Mirrors the live Profile's roleArns (was 8 entries, read from
# `aws rolesanywhere list-profiles --region us-west-2`). The variable default is
# ["user08"] only — applying with that default would have shrunk the Profile to
# one role and cut off the other seven pilots.
#
# admin is the 9th entry and is NOT an on-prem DGX pilot: it is the operator
# test identity (<ADMIN_EMAIL>). Roles Anywhere access for a role
# can only be verified by actually presenting a CA-signed certificate for it,
# and doing that against a real user's role would mean using that user's private
# key. admin exists so this chain — Trust Anchor -> Profile -> role trust ->
# CreateSession -> gateway call — can be exercised end to end under the
# operator's own identity after any change to the DGX access path.
dgx_pilot_users = [
  "admin", "user07", "user08", "user11", "user02", "user21", "user09", "user17",
  "user20",
]

# CA that signs the DGX client certificates. This is the exact bundle already
# installed on Trust Anchor 1cb998b6-d890-48cd-a605-48b8de749a40 (us-west-2),
# transcribed so that importing that Trust Anchor into state is a no-op instead
# of a replacement — a replacement would mint a new Trust Anchor ARN and the
# aws:SourceArn condition in the role trust policies would stop matching the
# ARN the DGX clients actually call.
#
#   subject/issuer  C=KR, O=ACME, OU=Infrastructure, CN=DGX-Gateway-CA
#   validity        2026-04-16 .. 2036-04-13
#   SHA-256         35:FB:68:63:BE:BE:1D:9E:BE:00:4F:3D:1B:22:88:D2:
#                   6F:80:FE:EE:0B:AD:16:FE:47:31:1D:15:94:81:40:D9
#
# Public certificate only — no private key material.
dgx_ca_certificate_pem = <<-EOT
-----BEGIN CERTIFICATE-----
<DGX_CLIENT_CA_CERTIFICATE_PEM>
-----END CERTIFICATE-----
EOT
