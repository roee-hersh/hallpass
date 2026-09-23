package googlecloud

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// action is one named question and the IAM permission it asks about.
type action struct {
	name, desc string
	// permission is the IAM permission, or "" for iam.set whose permission
	// depends on the resource type.
	permission string
	// types are the resource types the action is meant for. project, folder,
	// organization and name are accepted by every action: a permission can
	// be checked at any level of the hierarchy.
	types []string
}

var actionList = []action{
	{"project.view", "see a project (resourcemanager.projects.get)", "resourcemanager.projects.get", []string{"project"}},
	{"iam.set", "change the IAM policy of the resource (<type>.setIamPolicy)", "", []string{"project", "folder", "organization", "bucket", "secret", "serviceaccount", "table"}},
	{"storage.read", "read objects (storage.objects.get)", "storage.objects.get", []string{"bucket", "object"}},
	{"storage.write", "create objects (storage.objects.create)", "storage.objects.create", []string{"bucket", "object"}},
	{"storage.delete", "delete objects (storage.objects.delete)", "storage.objects.delete", []string{"bucket", "object"}},
	{"storage.list", "list objects (storage.objects.list)", "storage.objects.list", []string{"bucket"}},
	{"bucket.delete", "delete a bucket (storage.buckets.delete)", "storage.buckets.delete", []string{"bucket"}},
	{"bigquery.read", "read table data (bigquery.tables.getData)", "bigquery.tables.getData", []string{"dataset", "table"}},
	{"bigquery.write", "change table data (bigquery.tables.updateData)", "bigquery.tables.updateData", []string{"dataset", "table"}},
	{"bigquery.delete", "delete a table (bigquery.tables.delete)", "bigquery.tables.delete", []string{"dataset", "table"}},
	{"secret.read", "access secret versions (secretmanager.versions.access)", "secretmanager.versions.access", []string{"secret"}},
	{"serviceaccount.actas", "act as a service account (iam.serviceAccounts.actAs)", "iam.serviceAccounts.actAs", []string{"serviceaccount"}},
	{"compute.start", "start a VM (compute.instances.start)", "compute.instances.start", []string{"instance"}},
	{"compute.stop", "stop a VM (compute.instances.stop)", "compute.instances.stop", []string{"instance"}},
	{"compute.delete", "delete a VM (compute.instances.delete)", "compute.instances.delete", []string{"instance"}},
	{"run.deploy", "deploy a Cloud Run service (run.services.update)", "run.services.update", []string{"service"}},
	{"gke.access", "get a GKE cluster and its credentials (container.clusters.get)", "container.clusters.get", []string{"cluster"}},
}

var actionIndex = func() map[string]int {
	m := map[string]int{}
	for i, a := range actionList {
		m[a.name] = i
	}
	return m
}()

// setIamPolicyPermissions is the permission iam.set asks about per type.
var setIamPolicyPermissions = map[string]string{
	"project":        "resourcemanager.projects.setIamPolicy",
	"folder":         "resourcemanager.folders.setIamPolicy",
	"organization":   "resourcemanager.organizations.setIamPolicy",
	"bucket":         "storage.buckets.setIamPolicy",
	"secret":         "secretmanager.secrets.setIamPolicy",
	"serviceaccount": "iam.serviceAccounts.setIamPolicy",
	"table":          "bigquery.tables.setIamPolicy",
}

// hierarchyTypes are accepted by every action besides its own types.
var hierarchyTypes = map[string]bool{"project": true, "folder": true, "organization": true, "name": true}

const rawPattern = "raw:<permission>"

// Actions of the googlecloud integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList)+1)
	out = append(out, catalog.Action{Name: rawPattern, Pattern: true,
		Description: "any IAM permission, e.g. raw:storage.objects.delete, raw:iam.serviceAccounts.actAs, raw:compute.instances.setMetadata"})
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + strings.Join(a.types, ", ") + ")"})
	}
	return out
}

// permissionRe is the v1 permission format (service.resource.verb) and
// permissionV2Re the v2 one (service.googleapis.com/resource.verb).
var (
	permissionRe   = regexp.MustCompile(`^[a-z][a-zA-Z0-9]{0,63}(\.[a-zA-Z0-9]{1,64}){2,4}$`)
	permissionV2Re = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}\.googleapis\.com/[a-zA-Z0-9]{1,64}(\.[a-zA-Z0-9]{1,64}){1,3}$`)
)

// MatchAction accepts raw:<permission>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	if _, err := parseRaw(name); err != nil {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: rawPattern, Pattern: true, Description: "IAM permission " + strings.TrimPrefix(name, "raw:")}, true
}

func parseRaw(name string) (string, error) {
	p, ok := strings.CutPrefix(name, "raw:")
	if !ok {
		return "", fmt.Errorf("unknown action %q", name)
	}
	if !permissionRe.MatchString(p) && !permissionV2Re.MatchString(p) {
		return "", fmt.Errorf("raw action %q must name an IAM permission such as storage.objects.get", name)
	}
	return p, nil
}

var (
	projectIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	numberRe    = regexp.MustCompile(`^[0-9]{1,20}$`)
	bucketRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	datasetRe   = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	tableRe     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	secretRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	locationRe  = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	shortNameRe = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	saEmailRe   = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9])@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com$`)
	// hostRe is the start of every full resource name: a googleapis.com
	// service host followed by a path.
	hostRe = regexp.MustCompile(`^//[a-z][a-z0-9-]{0,62}\.googleapis\.com/.`)
	// nameCharsRe restricts the path of a name: resource, which arrives
	// verbatim, to the characters Google's documented full resource names use.
	nameCharsRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@:/+=~-]*$`)
)

// maxPiece bounds every name the regexes above leave unbounded (object
// names, dataset and table ids, full resource names). catalog caps the
// whole resource at 1024 bytes already; this keeps each piece explicit.
const maxPiece = 1024

// within reports whether s matches re and is at most maxPiece bytes.
func within(re *regexp.Regexp, s string) bool {
	return len(s) <= maxPiece && re.MatchString(s)
}

// isProject accepts a project id (6-30 lowercase letters, digits and
// hyphens) or a project number.
func isProject(s string) bool {
	return projectIDRe.MatchString(s) || numberRe.MatchString(s)
}

// isObjectName accepts a Cloud Storage object name: any bytes but control
// characters, at most 1024 bytes, without "." or ".." segments. The name
// only ever travels inside a JSON body.
func isObjectName(s string) bool {
	if s == "" || len(s) > maxPiece {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return !hasDotSegment(s)
}

// hasDotSegment reports whether any "/"-separated segment is "." or "..".
func hasDotSegment(s string) bool {
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// wellFormed is the invariant every full resource name hallpass sends
// satisfies, whichever type built it: a googleapis.com host, no control
// characters, no dot segments, at most maxPiece bytes.
func wellFormed(full string) bool {
	if len(full) > maxPiece || !hostRe.MatchString(full) || hasDotSegment(full) {
		return false
	}
	for _, c := range full {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// ref is one parsed question: the permission and the full resource name.
type ref struct {
	permission string
	resource   string
}

// parseRef validates the action and the resource and builds the access tuple.
func parseRef(actionName string, r catalog.Resource) (ref, error) {
	if len(r.Query) > 0 {
		return ref{}, invalid("resource %q must not carry a query", r.Raw)
	}
	full, err := fullResourceName(r)
	if err != nil {
		return ref{}, err
	}
	if !wellFormed(full) {
		return ref{}, invalid("resource %q does not form a valid full resource name", r.Raw)
	}
	out := ref{resource: full}
	if strings.HasPrefix(actionName, "raw:") {
		out.permission, err = parseRaw(actionName)
		if err != nil {
			return ref{}, invalid("%v", err)
		}
		return out, nil
	}
	i, ok := actionIndex[actionName]
	if !ok {
		return ref{}, invalid("unknown action %q", actionName)
	}
	a := actionList[i]
	if a.name == "iam.set" {
		p, ok := setIamPolicyPermissions[r.Type]
		if !ok {
			if r.Type == "name" {
				return ref{}, invalid("iam.set needs a typed resource to pick the setIamPolicy permission; use raw:<service>.<type>.setIamPolicy with name:")
			}
			return ref{}, invalid("iam.set is not defined for %s: resources", r.Type)
		}
		out.permission = p
		return out, nil
	}
	if !slices.Contains(a.types, r.Type) && !hierarchyTypes[r.Type] {
		return ref{}, invalid("action %s takes %s or a project, folder, organization or name resource, not %s:", a.name, strings.Join(a.types, ", "), r.Type)
	}
	out.permission = a.permission
	return out, nil
}

// fullResourceName turns a hallpass resource into a full resource name.
//
//	project:<id>                         //cloudresourcemanager.googleapis.com/projects/<id>
//	folder:<number>                      //cloudresourcemanager.googleapis.com/folders/<number>
//	organization:<number>                //cloudresourcemanager.googleapis.com/organizations/<number>
//	bucket:<name>                        //storage.googleapis.com/projects/_/buckets/<name>
//	object:<bucket>/<name>               //storage.googleapis.com/projects/_/buckets/<bucket>/objects/<name>
//	dataset:<project>/<dataset>          //bigquery.googleapis.com/projects/<p>/datasets/<d>
//	table:<project>/<dataset>/<table>    //bigquery.googleapis.com/projects/<p>/datasets/<d>/tables/<t>
//	secret:<project>/<name>              //secretmanager.googleapis.com/projects/<p>/secrets/<name>
//	serviceaccount:<email>               //iam.googleapis.com/projects/<p>/serviceAccounts/<email>
//	instance:<project>/<zone>/<name>     //compute.googleapis.com/projects/<p>/zones/<z>/instances/<name>
//	service:<project>/<location>/<name>  //run.googleapis.com/projects/<p>/locations/<l>/services/<name>
//	cluster:<project>/<location>/<name>  //container.googleapis.com/projects/<p>/locations/<l>/clusters/<name>
//	name:<full resource name>            verbatim
func fullResourceName(r catalog.Resource) (string, error) {
	id := r.ID
	switch r.Type {
	case "project":
		if !isProject(id) {
			return "", invalid("project: id must be a project id (6-30 lowercase letters, digits and hyphens) or a project number")
		}
		return "//cloudresourcemanager.googleapis.com/projects/" + id, nil
	case "folder", "organization":
		if !numberRe.MatchString(id) {
			return "", invalid("%s: id must be a number", r.Type)
		}
		return "//cloudresourcemanager.googleapis.com/" + r.Type + "s/" + id, nil
	case "bucket":
		if !bucketRe.MatchString(id) {
			return "", invalid("bucket: id must be a bucket name")
		}
		return "//storage.googleapis.com/projects/_/buckets/" + id, nil
	case "object":
		bucket, object, ok := strings.Cut(id, "/")
		if !ok || !bucketRe.MatchString(bucket) || !isObjectName(object) {
			return "", invalid("object: id must be <bucket>/<object name>, without . or .. segments")
		}
		return "//storage.googleapis.com/projects/_/buckets/" + bucket + "/objects/" + object, nil
	case "dataset":
		parts := strings.Split(id, "/")
		if len(parts) != 2 || !isProject(parts[0]) || !within(datasetRe, parts[1]) {
			return "", invalid("dataset: id must be <project>/<dataset>")
		}
		return "//bigquery.googleapis.com/projects/" + parts[0] + "/datasets/" + parts[1], nil
	case "table":
		parts := strings.Split(id, "/")
		if len(parts) != 3 || !isProject(parts[0]) || !within(datasetRe, parts[1]) || !within(tableRe, parts[2]) {
			return "", invalid("table: id must be <project>/<dataset>/<table>")
		}
		return "//bigquery.googleapis.com/projects/" + parts[0] + "/datasets/" + parts[1] + "/tables/" + parts[2], nil
	case "secret":
		parts := strings.Split(id, "/")
		if len(parts) != 2 || !isProject(parts[0]) || !secretRe.MatchString(parts[1]) {
			return "", invalid("secret: id must be <project>/<secret name>")
		}
		return "//secretmanager.googleapis.com/projects/" + parts[0] + "/secrets/" + parts[1], nil
	case "serviceaccount":
		m := saEmailRe.FindStringSubmatch(strings.ToLower(id))
		if m == nil {
			return "", invalid("serviceaccount: id must be a <name>@<project>.iam.gserviceaccount.com address; use name: for Google-managed accounts")
		}
		return "//iam.googleapis.com/projects/" + m[2] + "/serviceAccounts/" + strings.ToLower(id), nil
	case "instance", "service", "cluster":
		parts := strings.Split(id, "/")
		if len(parts) != 3 || !isProject(parts[0]) || !locationRe.MatchString(parts[1]) || !shortNameRe.MatchString(parts[2]) {
			return "", invalid("%s: id must be <project>/<location>/<name>", r.Type)
		}
		switch r.Type {
		case "instance":
			return "//compute.googleapis.com/projects/" + parts[0] + "/zones/" + parts[1] + "/instances/" + parts[2], nil
		case "service":
			return "//run.googleapis.com/projects/" + parts[0] + "/locations/" + parts[1] + "/services/" + parts[2], nil
		default:
			return "//container.googleapis.com/projects/" + parts[0] + "/locations/" + parts[1] + "/clusters/" + parts[2], nil
		}
	case "name":
		host, path, _ := strings.Cut(strings.TrimPrefix(id, "//"), "/")
		if !wellFormed(id) || host == "" || !nameCharsRe.MatchString(path) {
			return "", invalid("name: id must be a full resource name such as //cloudresourcemanager.googleapis.com/projects/my-project")
		}
		return id, nil
	}
	return "", invalid("resource type %q is not one of project, folder, organization, bucket, object, dataset, table, secret, serviceaccount, instance, service, cluster, name", r.Type)
}
