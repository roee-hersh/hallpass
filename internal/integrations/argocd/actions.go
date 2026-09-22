package argocd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integrations/argocd/rbac"
)

// actRollback is resolved at check time to sync or rollback depending on
// server.rbac.rollback.enforce.enable.
const actRollback = "\x00rollback"

type action struct {
	name, desc string
	res, act   string
}

var actionList = []action{
	{"app.get", "view an application", rbac.ResourceApplications, rbac.ActionGet},
	{"app.create", "create an application", rbac.ResourceApplications, rbac.ActionCreate},
	{"app.update", "update an application", rbac.ResourceApplications, rbac.ActionUpdate},
	{"app.delete", "delete an application", rbac.ResourceApplications, rbac.ActionDelete},
	{"app.sync", "sync an application", rbac.ResourceApplications, rbac.ActionSync},
	{"app.rollback", "roll an application back (sync, or rollback when server.rbac.rollback.enforce.enable is on)", rbac.ResourceApplications, actRollback},
	{"app.override", "override application parameters", rbac.ResourceApplications, rbac.ActionOverride},
	{"logs.get", "read pod logs of an application", rbac.ResourceLogs, rbac.ActionGet},
	{"exec.create", "exec into a pod of an application", rbac.ResourceExec, rbac.ActionCreate},
	{"appset.get", "view an ApplicationSet", rbac.ResourceApplicationSets, rbac.ActionGet},
	{"appset.create", "create an ApplicationSet", rbac.ResourceApplicationSets, rbac.ActionCreate},
	{"appset.update", "update an ApplicationSet", rbac.ResourceApplicationSets, rbac.ActionUpdate},
	{"appset.delete", "delete an ApplicationSet", rbac.ResourceApplicationSets, rbac.ActionDelete},
	{"project.get", "view a project", rbac.ResourceProjects, rbac.ActionGet},
	{"project.create", "create a project", rbac.ResourceProjects, rbac.ActionCreate},
	{"project.update", "update a project", rbac.ResourceProjects, rbac.ActionUpdate},
	{"project.delete", "delete a project", rbac.ResourceProjects, rbac.ActionDelete},
	{"cluster.get", "view a cluster", rbac.ResourceClusters, rbac.ActionGet},
	{"cluster.create", "add a cluster", rbac.ResourceClusters, rbac.ActionCreate},
	{"cluster.update", "update a cluster", rbac.ResourceClusters, rbac.ActionUpdate},
	{"cluster.delete", "remove a cluster", rbac.ResourceClusters, rbac.ActionDelete},
	{"repo.get", "view a repository", rbac.ResourceRepositories, rbac.ActionGet},
	{"repo.create", "add a repository", rbac.ResourceRepositories, rbac.ActionCreate},
	{"repo.update", "update a repository", rbac.ResourceRepositories, rbac.ActionUpdate},
	{"repo.delete", "remove a repository", rbac.ResourceRepositories, rbac.ActionDelete},
	{"writerepo.get", "view a write repository", rbac.ResourceWriteRepositories, rbac.ActionGet},
	{"writerepo.create", "add a write repository", rbac.ResourceWriteRepositories, rbac.ActionCreate},
	{"writerepo.update", "update a write repository", rbac.ResourceWriteRepositories, rbac.ActionUpdate},
	{"writerepo.delete", "remove a write repository", rbac.ResourceWriteRepositories, rbac.ActionDelete},
	{"certificate.get", "view a certificate", rbac.ResourceCertificates, rbac.ActionGet},
	{"certificate.create", "add a certificate", rbac.ResourceCertificates, rbac.ActionCreate},
	{"certificate.update", "update a certificate", rbac.ResourceCertificates, rbac.ActionUpdate},
	{"certificate.delete", "remove a certificate", rbac.ResourceCertificates, rbac.ActionDelete},
	{"account.get", "view an account", rbac.ResourceAccounts, rbac.ActionGet},
	{"account.update", "update an account", rbac.ResourceAccounts, rbac.ActionUpdate},
	{"gpgkey.get", "view a GPG key", rbac.ResourceGPGKeys, rbac.ActionGet},
	{"gpgkey.create", "add a GPG key", rbac.ResourceGPGKeys, rbac.ActionCreate},
	{"gpgkey.delete", "remove a GPG key", rbac.ResourceGPGKeys, rbac.ActionDelete},
	{"extension.invoke", "invoke an extension", rbac.ResourceExtensions, rbac.ActionInvoke},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// resourceTypes maps hallpass resource types to Argo CD resources.
var resourceTypes = map[string]string{
	"applications":       rbac.ResourceApplications,
	"applicationsets":    rbac.ResourceApplicationSets,
	"logs":               rbac.ResourceLogs,
	"exec":               rbac.ResourceExec,
	"projects":           rbac.ResourceProjects,
	"clusters":           rbac.ResourceClusters,
	"repositories":       rbac.ResourceRepositories,
	"write_repositories": rbac.ResourceWriteRepositories,
	"certificates":       rbac.ResourceCertificates,
	"accounts":           rbac.ResourceAccounts,
	"gpgkeys":            rbac.ResourceGPGKeys,
	"extensions":         rbac.ResourceExtensions,
}

// request is what goes into the enforcer.
type request struct {
	res, act, obj string
	// fineGrained update/delete carry the top-level verb for v2 inheritance.
	fineGrained bool
	topAct      string
}

var (
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
	// objRe bounds the object string. It is matched as a value, never as a
	// pattern, so it only needs to be printable.
	objRe = regexp.MustCompile(`^[^\x00-\x20\x7f]{1,512}$`)
)

// parsePattern recognises app.action/<g>/<k>/<a>, app.update/<g>/<k>/<ns>/<n>
// and app.delete/<g>/<k>/<ns>/<n>.
func parsePattern(name string) (request, bool) {
	prefix, rest, ok := strings.Cut(name, "/")
	if !ok {
		return request{}, false
	}
	parts := strings.Split(rest, "/")
	for _, p := range parts {
		if p != "" && !segmentRe.MatchString(p) {
			return request{}, false
		}
	}
	switch prefix {
	case "app.action":
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return request{}, false
		}
		return request{res: rbac.ResourceApplications, act: rbac.ActionAction + "/" + rest}, true
	case "app.update", "app.delete":
		if len(parts) != 4 || parts[1] == "" || parts[3] == "" {
			return request{}, false
		}
		verb := strings.TrimPrefix(prefix, "app.")
		return request{res: rbac.ResourceApplications, act: verb + "/" + rest, fineGrained: true, topAct: verb}, true
	}
	return request{}, false
}

// buildRequest combines the action and the resource.
func buildRequest(actionName string, res catalog.Resource) (request, error) {
	var req request
	if a, ok := actions[actionName]; ok {
		req = request{res: a.res, act: a.act}
	} else if p, ok := parsePattern(actionName); ok {
		req = p
	} else {
		return req, fmt.Errorf("unknown action %q", actionName)
	}
	argoRes, ok := resourceTypes[res.Type]
	if !ok {
		return req, fmt.Errorf("resource type %q; use one of applications, applicationsets, logs, exec, projects, clusters, repositories, write_repositories, certificates, accounts, gpgkeys, extensions", res.Type)
	}
	// logs and exec take an applications resource too, since the object is the same.
	if argoRes != req.res && !((req.res == rbac.ResourceLogs || req.res == rbac.ResourceExec) && argoRes == rbac.ResourceApplications) {
		return req, fmt.Errorf("action %s applies to %s, but the resource is %s", actionName, req.res, res.Type)
	}
	if res.ID == "" {
		return req, errors.New("resource needs an id, e.g. applications:<project>/<name>")
	}
	if !objRe.MatchString(res.ID) {
		return req, errors.New("resource id contains whitespace or control characters")
	}
	if rbac.ProjectScoped[req.res] && req.res != rbac.ResourceClusters && req.res != rbac.ResourceRepositories {
		if !strings.Contains(res.ID, "/") {
			return req, fmt.Errorf("%s resources are <project>/<name>", res.Type)
		}
	}
	req.obj = res.ID
	return req, nil
}
