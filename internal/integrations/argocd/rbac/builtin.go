package rbac

import _ "embed"

// BuiltinPolicyCSV is Argo CD's assets/builtin-policy.csv. It defines
// role:readonly and role:admin and binds the admin user.
//
// Copied from Argo CD v3.5.3 (the latest release on 2026-09-21). It changes
// rarely; diff it against the version you run if a builtin role answers
// unexpectedly. Unreleased master adds "p, role:admin, applications,
// rollback, */*, allow", which matters only with
// server.rbac.rollback.enforce.enable.
//
//go:embed builtin-policy.csv
var BuiltinPolicyCSV string
