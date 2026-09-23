package databricks

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Two permission systems live in one workspace. Unity Catalog securables
// (catalog, schema, table, volume, function, model) carry privileges such
// as SELECT and MODIFY, inherited down the hierarchy. Workspace objects
// (clusters, jobs, warehouses, notebooks, ...) carry permission levels such
// as CAN_ATTACH_TO and CAN_MANAGE from the Permissions API.

// ucTypes maps a hallpass resource type to the Unity Catalog securable type
// in the API path and the number of dot-separated name parts it takes.
var ucTypes = map[string]struct {
	securable string
	parts     int
}{
	"catalog":  {"catalog", 1},
	"schema":   {"schema", 2},
	"table":    {"table", 3},
	"volume":   {"volume", 3},
	"function": {"function", 3},
	"model":    {"model", 3},
}

// wsTypes maps a hallpass resource type to the Permissions API object type
// and the permission levels it knows, weakest first. A stronger level
// implies every weaker one in the same chain; CAN_MANAGE and IS_OWNER
// imply everything.
var wsTypes = map[string]struct {
	object string
	chains [][]string
}{
	"cluster":          {"clusters", [][]string{{"CAN_ATTACH_TO", "CAN_RESTART", "CAN_MANAGE"}}},
	"policy":           {"cluster-policies", [][]string{{"CAN_USE"}}},
	"pool":             {"instance-pools", [][]string{{"CAN_ATTACH_TO", "CAN_MANAGE"}}},
	"job":              {"jobs", [][]string{{"CAN_VIEW", "CAN_MANAGE_RUN", "IS_OWNER", "CAN_MANAGE"}}},
	"pipeline":         {"pipelines", [][]string{{"CAN_VIEW", "CAN_RUN", "IS_OWNER", "CAN_MANAGE"}}},
	"warehouse":        {"warehouses", [][]string{{"CAN_VIEW", "CAN_MONITOR", "CAN_MANAGE"}, {"CAN_VIEW", "CAN_USE", "IS_OWNER", "CAN_MANAGE"}}},
	"notebook":         {"notebooks", [][]string{{"CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"}}},
	"directory":        {"directories", [][]string{{"CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"}}},
	"repo":             {"repos", [][]string{{"CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"}}},
	"endpoint":         {"serving-endpoints", [][]string{{"CAN_VIEW", "CAN_QUERY", "CAN_MANAGE"}}},
	"experiment":       {"experiments", [][]string{{"CAN_READ", "CAN_EDIT", "CAN_MANAGE"}}},
	"registered_model": {"registered-models", [][]string{{"CAN_READ", "CAN_EDIT", "CAN_MANAGE_STAGING_VERSIONS", "CAN_MANAGE_PRODUCTION_VERSIONS", "CAN_MANAGE"}}},
}

// action is one named question.
type action struct {
	name, desc string
	// types are the resource types the action applies to.
	types []string
	// privileges are the Unity Catalog privileges that must all be held
	// (for a UC action); level is the permission level needed (for a
	// workspace action).
	privileges []string
	level      string
}

const (
	privSelect        = "SELECT"
	privModify        = "MODIFY"
	privUseCatalog    = "USE_CATALOG"
	privUseSchema     = "USE_SCHEMA"
	privCreateTable   = "CREATE_TABLE"
	privCreateSchema  = "CREATE_SCHEMA"
	privReadVolume    = "READ_VOLUME"
	privWriteVolume   = "WRITE_VOLUME"
	privExecute       = "EXECUTE"
	privManage        = "MANAGE"
	privAllPrivileges = "ALL_PRIVILEGES"
	// privUsage is the legacy name that stood for both USE_CATALOG and
	// USE_SCHEMA before they were split.
	privUsage = "USAGE"
)

var actionList = []action{
	{name: "table.read", desc: "read a table or view: SELECT with USE_SCHEMA and USE_CATALOG", types: []string{"table"}, privileges: []string{privSelect, privUseSchema, privUseCatalog}},
	{name: "table.write", desc: "change a table's data: MODIFY with USE_SCHEMA and USE_CATALOG", types: []string{"table"}, privileges: []string{privModify, privUseSchema, privUseCatalog}},
	{name: "table.create", desc: "create a table in a schema: CREATE_TABLE with USE_SCHEMA and USE_CATALOG", types: []string{"schema"}, privileges: []string{privCreateTable, privUseSchema, privUseCatalog}},
	{name: "schema.create", desc: "create a schema in a catalog: CREATE_SCHEMA with USE_CATALOG", types: []string{"catalog"}, privileges: []string{privCreateSchema, privUseCatalog}},
	{name: "catalog.use", desc: "use a catalog: USE_CATALOG", types: []string{"catalog"}, privileges: []string{privUseCatalog}},
	{name: "volume.read", desc: "read files in a volume: READ_VOLUME with USE_SCHEMA and USE_CATALOG", types: []string{"volume"}, privileges: []string{privReadVolume, privUseSchema, privUseCatalog}},
	{name: "volume.write", desc: "write files in a volume: WRITE_VOLUME with USE_SCHEMA and USE_CATALOG", types: []string{"volume"}, privileges: []string{privWriteVolume, privUseSchema, privUseCatalog}},
	{name: "function.execute", desc: "call a function: EXECUTE with USE_SCHEMA and USE_CATALOG", types: []string{"function"}, privileges: []string{privExecute, privUseSchema, privUseCatalog}},
	{name: "uc.manage", desc: "manage grants on a Unity Catalog securable: MANAGE, or ownership", types: []string{"catalog", "schema", "table", "volume", "function", "model"}, privileges: []string{privManage}},
	{name: "cluster.attach", desc: "attach to a cluster (CAN_ATTACH_TO)", types: []string{"cluster"}, level: "CAN_ATTACH_TO"},
	{name: "cluster.restart", desc: "restart a cluster (CAN_RESTART)", types: []string{"cluster"}, level: "CAN_RESTART"},
	{name: "cluster.manage", desc: "manage a cluster (CAN_MANAGE)", types: []string{"cluster"}, level: "CAN_MANAGE"},
	{name: "job.view", desc: "view a job and its runs (CAN_VIEW)", types: []string{"job"}, level: "CAN_VIEW"},
	{name: "job.run", desc: "trigger and cancel a job's runs (CAN_MANAGE_RUN)", types: []string{"job"}, level: "CAN_MANAGE_RUN"},
	{name: "job.manage", desc: "edit and delete a job (CAN_MANAGE)", types: []string{"job"}, level: "CAN_MANAGE"},
	{name: "warehouse.use", desc: "run queries on a SQL warehouse (CAN_USE)", types: []string{"warehouse"}, level: "CAN_USE"},
	{name: "warehouse.manage", desc: "manage a SQL warehouse (CAN_MANAGE)", types: []string{"warehouse"}, level: "CAN_MANAGE"},
	{name: "notebook.read", desc: "read a notebook, directory or repo (CAN_READ)", types: []string{"notebook", "directory", "repo"}, level: "CAN_READ"},
	{name: "notebook.run", desc: "run a notebook, or notebooks in a directory or repo (CAN_RUN)", types: []string{"notebook", "directory", "repo"}, level: "CAN_RUN"},
	{name: "notebook.edit", desc: "edit a notebook, directory or repo (CAN_EDIT)", types: []string{"notebook", "directory", "repo"}, level: "CAN_EDIT"},
	{name: "pipeline.run", desc: "start and stop a pipeline (CAN_RUN)", types: []string{"pipeline"}, level: "CAN_RUN"},
	{name: "endpoint.query", desc: "query a model serving endpoint (CAN_QUERY)", types: []string{"endpoint"}, level: "CAN_QUERY"},
}

var actionIndex = func() map[string]int {
	m := map[string]int{}
	for i, a := range actionList {
		m[a.name] = i
	}
	return m
}()

const rawPattern = "raw:<PRIVILEGE or LEVEL>"

// Actions of the databricks integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList)+1)
	out = append(out, catalog.Action{Name: rawPattern, Pattern: true,
		Description: "one Unity Catalog privilege on a catalog/schema/table/volume/function/model (raw:SELECT, raw:CREATE_VOLUME) or one permission level on a workspace object (raw:CAN_RESTART, raw:IS_OWNER)"})
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + strings.Join(a.types, ", ") + ")"})
	}
	return out
}

var rawRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

// MatchAction accepts raw:<PRIVILEGE or LEVEL>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	if _, err := parseRaw(name); err != nil {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: rawPattern, Pattern: true, Description: "privilege or permission level " + strings.TrimPrefix(name, "raw:")}, true
}

func parseRaw(name string) (string, error) {
	p, ok := strings.CutPrefix(name, "raw:")
	if !ok {
		return "", fmt.Errorf("unknown action %q", name)
	}
	if !rawRe.MatchString(p) {
		return "", fmt.Errorf("raw action %q must name a privilege or permission level in upper case, such as raw:SELECT or raw:CAN_RESTART", name)
	}
	return p, nil
}

var (
	// ucNameRe is one part of a Unity Catalog name. Names are quoted in SQL
	// with backticks and may hold more, but hallpass only places them in a
	// URL path segment, so it keeps to the unquoted identifier shape.
	ucNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	// wsIDRe is a workspace object id: cluster ids like 0123-456789-abcde1f2,
	// numeric job, notebook and warehouse ids, UUIDs, endpoint names.
	wsIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
)

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// ref is one parsed question.
type ref struct {
	// uc is set for a Unity Catalog question.
	uc         bool
	securable  string   // catalog, schema, table, ...
	fullName   string   // catalog.schema.table
	privileges []string // every one must be held
	// object and id are set for a workspace object question.
	object string // clusters, jobs, ...
	id     string
	level  string
	chains [][]string
}

// parseRef validates the action and the resource together.
func parseRef(actionName string, r catalog.Resource) (ref, error) {
	if len(r.Query) > 0 {
		return ref{}, invalid("resource %q must not carry a query", r.Raw)
	}
	var out ref
	if uc, ok := ucTypes[r.Type]; ok {
		parts := strings.Split(r.ID, ".")
		if len(parts) != uc.parts {
			return ref{}, invalid("%s: id must have %d dot-separated parts, as in %s", r.Type, uc.parts, ucExample(r.Type))
		}
		for _, p := range parts {
			if !ucNameRe.MatchString(p) {
				return ref{}, invalid("%s: %q is not a Unity Catalog name", r.Type, p)
			}
		}
		out = ref{uc: true, securable: uc.securable, fullName: r.ID}
	} else if ws, ok := wsTypes[r.Type]; ok {
		if !wsIDRe.MatchString(r.ID) {
			return ref{}, invalid("%s: id must be the object's id", r.Type)
		}
		out = ref{object: ws.object, id: r.ID, chains: ws.chains}
	} else {
		return ref{}, invalid("resource type %q is not one of %s", r.Type, strings.Join(resourceTypes(), ", "))
	}
	if strings.HasPrefix(actionName, "raw:") {
		p, err := parseRaw(actionName)
		if err != nil {
			return ref{}, invalid("%v", err)
		}
		if out.uc {
			out.privileges = []string{p}
			return out, nil
		}
		if !knownLevel(out.chains, p) {
			return ref{}, invalid("%s is not a permission level of %s; the levels are %s", p, r.Type, strings.Join(levelsOf(out.chains), ", "))
		}
		out.level = p
		return out, nil
	}
	i, ok := actionIndex[actionName]
	if !ok {
		return ref{}, invalid("unknown action %q", actionName)
	}
	a := actionList[i]
	if !slices.Contains(a.types, r.Type) {
		return ref{}, invalid("action %s takes a %s resource, not %s:", a.name, strings.Join(a.types, " or "), r.Type)
	}
	out.privileges, out.level = a.privileges, a.level
	return out, nil
}

func ucExample(typ string) string {
	switch ucTypes[typ].parts {
	case 1:
		return typ + ":main"
	case 2:
		return typ + ":main.sales"
	}
	return typ + ":main.sales.orders"
}

func resourceTypes() []string {
	var out []string
	for t := range ucTypes {
		out = append(out, t)
	}
	for t := range wsTypes {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// knownLevel reports whether the level exists for an object with these
// chains. CAN_MANAGE and IS_OWNER exist for every type.
func knownLevel(chains [][]string, level string) bool {
	return level == "CAN_MANAGE" || level == "IS_OWNER" || slices.Contains(levelsOf(chains), level)
}

// levelsOf lists the distinct levels of the chains, in chain order.
func levelsOf(chains [][]string) []string {
	var out []string
	for _, chain := range chains {
		for _, l := range chain {
			if !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
	}
	return out
}

// satisfiesLevel reports whether one of the held permission levels implies
// need for an object with the given chains. CAN_MANAGE and IS_OWNER imply
// every level but IS_OWNER itself, which names the one owner; within a
// chain a level implies the ones before it.
func satisfiesLevel(held []string, need string, chains [][]string) (bool, string) {
	for _, h := range held {
		if h == need {
			return true, h
		}
		if need == "IS_OWNER" {
			continue
		}
		if h == "CAN_MANAGE" || h == "IS_OWNER" {
			return true, h
		}
		for _, chain := range chains {
			hi, ni := slices.Index(chain, h), slices.Index(chain, need)
			if hi >= 0 && ni >= 0 && hi > ni {
				return true, h
			}
		}
	}
	return false, ""
}

// heldPrivileges is what the user holds on a securable: named privileges,
// and the securable types (the securable's own, or an ancestor's) on which
// ALL_PRIVILEGES was granted.
type heldPrivileges struct {
	named map[string]bool
	// allOn lists the securable types carrying an ALL_PRIVILEGES grant that
	// reaches this securable: "table" for a grant on the table itself,
	// "schema" or "catalog" for an inherited one.
	allOn []string
}

func newHeld() heldPrivileges { return heldPrivileges{named: map[string]bool{}} }

// covers reports whether a grant of everything on a securable of type scope
// (ALL_PRIVILEGES there, or ownership of it) stands for the privilege when
// asked about a descendant. USE_CATALOG lives on the catalog and USE_SCHEMA
// on the schema, so a grant lower down never carries them. ALL_PRIVILEGES
// does not include MANAGE; ownership does.
func covers(scope, privilege string, owner bool) bool {
	switch privilege {
	case privUseCatalog:
		return scope == "catalog"
	case privUseSchema:
		return scope == "catalog" || scope == "schema"
	case privManage:
		return owner
	}
	return true
}

// satisfiesPrivileges reports whether the held privileges cover every
// needed one, and which are missing. The legacy USAGE covers USE_CATALOG
// and USE_SCHEMA.
func satisfiesPrivileges(held heldPrivileges, need []string) (bool, []string) {
	var missing []string
	for _, n := range need {
		if held.named[n] || ((n == privUseCatalog || n == privUseSchema) && held.named[privUsage]) {
			continue
		}
		if slices.ContainsFunc(held.allOn, func(scope string) bool { return covers(scope, n, false) }) {
			continue
		}
		missing = append(missing, n)
	}
	return len(missing) == 0, missing
}
