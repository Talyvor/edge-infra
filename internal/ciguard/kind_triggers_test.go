package ciguard

// ── WHY THIS EXISTS (B28.198) ────────────────────────────────────────────────
//
// The kind workflows (kind-e2e, kind-cutover, kind-rollback) build every image
// from the working tree — deploy/local/up.sh `docker build`s the control plane,
// the OSB broker and the auth-service — and then prove the stack end to end. But
// they are path-filtered, and the filters named the charts and the harness, not
// the code inside the images. A change to internal/xds, osb/broker.py or
// auth-service/src merged without the one workflow that runs it in a cluster.
//
// This guard derives the image-build inputs from the build itself — the
// `docker build` lines in deploy/local/*.sh, the COPY sources of each Dockerfile
// they name, and the Go package closure of every `go build` in those Dockerfiles
// — and fails if any tracked input file would not trigger every kind workflow on
// both push and pull_request.

import (
	"bufio"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// externalBuilds are `docker build` lines whose Dockerfile is NOT a working-tree
// path, with the reason no working-tree change can alter that image. Any other
// build whose Dockerfile does not resolve under $REPO_ROOT fails the guard, so a
// new build cannot be skipped silently.
var externalBuilds = map[string]string{
	`cutover.sh: "$src/Dockerfile.cutover-pin"`: "built from `git archive $PIN`, a fixed commit — no working-tree path can change it",
}

// dockerBuild is one `docker build` in the kind harness, repo-relative.
type dockerBuild struct {
	script     string
	dockerfile string
	context    string
}

// buildInput is one thing an image is built from, and the tracked files it covers.
type buildInput struct {
	origin string // human-readable: which build and which instruction
	files  []string
}

var (
	repoRootVarRE = regexp.MustCompile(`^\$\{?REPO_ROOT\}?/?`)
	goBuildPkgRE  = regexp.MustCompile(`(?:^|\s)(\./[^\s]+)`)
)

// joinContinuations folds backslash-continued lines into one logical line.
func joinContinuations(src string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, `\`) {
			cur.WriteString(strings.TrimSuffix(trimmed, `\`))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

// shellFields splits a command line on whitespace, keeping quoted words whole and
// stripping one layer of quotes.
func shellFields(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// repoPath maps a harness path ("$REPO_ROOT/osb/Dockerfile") to a repo-relative
// one ("osb/Dockerfile"). ok is false for any path not rooted at $REPO_ROOT.
func repoPath(p string) (string, bool) {
	loc := repoRootVarRE.FindStringIndex(p)
	if loc == nil {
		return "", false
	}
	rel := path.Clean(p[loc[1]:])
	if rel == "" {
		rel = "."
	}
	return rel, true
}

// collectDockerBuilds finds every `docker build` in deploy/local/*.sh.
func collectDockerBuilds(t *testing.T, root string) []dockerBuild {
	t.Helper()
	scripts, err := filepath.Glob(filepath.Join(root, "deploy", "local", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	valued := map[string]bool{"-f": true, "--file": true, "-t": true, "--tag": true,
		"--target": true, "--build-arg": true, "--platform": true}
	var out []dockerBuild
	for _, s := range scripts {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(s)
		for _, line := range joinContinuations(string(b)) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "docker build ") {
				continue
			}
			fields := shellFields(trimmed[strings.Index(trimmed, "docker build ")+len("docker build "):])
			var dockerfile, rawDockerfile string
			var positional []string
			for i := 0; i < len(fields); i++ {
				f := fields[i]
				if valued[f] && i+1 < len(fields) {
					if f == "-f" || f == "--file" {
						rawDockerfile = fields[i+1]
					}
					i++
					continue
				}
				if strings.HasPrefix(f, "-") {
					if v, ok := strings.CutPrefix(f, "--file="); ok {
						rawDockerfile = v
					}
					continue
				}
				positional = append(positional, f)
			}
			if len(positional) == 0 {
				t.Fatalf("%s: cannot find the build context in %q", name, trimmed)
			}
			key := name + `: "` + rawDockerfile + `"`
			if _, ok := externalBuilds[key]; ok {
				continue
			}
			ctx, okCtx := repoPath(positional[len(positional)-1])
			if rawDockerfile == "" {
				dockerfile = path.Join(ctx, "Dockerfile")
			} else {
				var okDf bool
				dockerfile, okDf = repoPath(rawDockerfile)
				okCtx = okCtx && okDf
			}
			if !okCtx {
				t.Fatalf("%s builds an image from a path outside $REPO_ROOT (%q). If no working-tree "+
					"change can alter that image, add `%s` to externalBuilds with the reason; otherwise "+
					"build it from $REPO_ROOT so this guard can see its inputs", name, trimmed, key)
			}
			bld := dockerBuild{script: name, dockerfile: dockerfile, context: ctx}
			if !slices.ContainsFunc(out, func(o dockerBuild) bool {
				return o.dockerfile == bld.dockerfile && o.context == bld.context
			}) {
				out = append(out, bld) // one Dockerfile, several --target: same inputs
			}
		}
	}
	return out
}

// trackedFiles lists every file git tracks, repo-relative with forward slashes.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var out []string
	for _, f := range strings.Split(string(b), "\x00") {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// under returns the tracked files at p: p itself, or everything below it.
func under(tracked []string, p string) []string {
	var out []string
	for _, f := range tracked {
		if f == p || p == "." || strings.HasPrefix(f, p+"/") {
			out = append(out, f)
		}
	}
	return out
}

// goClosure returns the module-local inputs of `go build pkgs` for linux: every
// tracked file directly inside each package directory, plus its embedded files.
func goClosure(t *testing.T, root string, tracked []string, pkgs []string) []string {
	t.Helper()
	args := append([]string{"list", "-deps", "-f",
		`{{if not .Standard}}{{.Dir}}{{range .EmbedFiles}}|{{.}}{{end}}{{"\n"}}{{end}}`}, pkgs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %v: %v", pkgs, err)
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "|")
		rel, err := filepath.Rel(root, parts[0])
		if err != nil || strings.HasPrefix(rel, "..") {
			continue // a dependency outside the module, fixed by go.sum
		}
		dir := filepath.ToSlash(rel)
		for _, f := range tracked {
			if path.Dir(f) == dir {
				out = append(out, f)
			}
		}
		for _, e := range parts[1:] {
			out = append(out, path.Join(dir, e))
		}
	}
	return out
}

// collectBuildInputs resolves every build to the tracked files it is built from.
func collectBuildInputs(t *testing.T, root string, tracked []string, builds []dockerBuild) []buildInput {
	t.Helper()
	var out []buildInput
	for _, bld := range builds {
		origin := bld.script + " → " + bld.dockerfile
		out = append(out, buildInput{origin: origin, files: under(tracked, bld.dockerfile)})

		src, err := os.ReadFile(filepath.Join(root, bld.dockerfile))
		if err != nil {
			t.Fatal(err)
		}
		var goPkgs []string
		wholeContext := false
		for _, line := range joinContinuations(string(src)) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch strings.ToUpper(fields[0]) {
			case "RUN":
				if i := strings.Index(line, "go build"); i >= 0 {
					for _, m := range goBuildPkgRE.FindAllStringSubmatch(line[i:], -1) {
						goPkgs = append(goPkgs, m[1])
					}
				}
			case "COPY", "ADD":
				var args []string
				fromStage := false
				for _, f := range fields[1:] {
					if strings.HasPrefix(f, "--from") {
						fromStage = true
					}
					if !strings.HasPrefix(f, "--") {
						args = append(args, f)
					}
				}
				if fromStage {
					continue
				}
				if len(args) < 2 || strings.HasPrefix(args[0], "[") {
					t.Fatalf("%s: cannot parse %q (JSON-form COPY is not modelled)", bld.dockerfile, line)
				}
				for _, s := range args[:len(args)-1] {
					p := path.Join(bld.context, s)
					if s == "." || s == "./" {
						wholeContext = true
						continue
					}
					files := under(tracked, p)
					if strings.ContainsAny(s, "*?[") {
						files = nil
						for _, f := range tracked {
							if ok, _ := path.Match(p, f); ok {
								files = append(files, f)
							}
						}
					}
					if len(files) == 0 {
						continue // staged at build time (e.g. dist/), never a tracked path
					}
					out = append(out, buildInput{origin: origin + " COPY " + s, files: files})
				}
			}
		}
		if wholeContext {
			if len(goPkgs) == 0 {
				t.Fatalf("%s copies its whole context (%s) and builds no Go package — this guard "+
					"cannot narrow that to a path list; copy explicit paths instead", bld.dockerfile, bld.context)
			}
			out = append(out, buildInput{
				origin: origin + " COPY . (go build " + strings.Join(goPkgs, " ") + ")",
				files:  goClosure(t, root, tracked, goPkgs),
			})
		}
	}
	return out
}

// workflowFile is the slice of a workflow the guards in this package read.
type workflowFile struct {
	On   map[string]*workflowTrigger `yaml:"on"`
	Jobs map[string]struct {
		Uses  string `yaml:"uses"`
		Steps []struct {
			Run string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
	// CalledByPR: pr.yaml calls this workflow, so its pull requests run on its
	// on.push.paths (B33.2).
	CalledByPR bool `yaml:"-"`
}

// workflowTrigger is one `on:` event: a mapping for push / pull_request, and for
// `schedule:` a list of `- cron:` entries.
type workflowTrigger struct {
	Paths       []string `yaml:"paths"`
	PathsIgnore []string `yaml:"paths-ignore"`
	Crons       []string `yaml:"-"`
}

func (w *workflowTrigger) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		var entries []struct {
			Cron string `yaml:"cron"`
		}
		if err := n.Decode(&entries); err != nil {
			return err
		}
		for _, e := range entries {
			w.Crons = append(w.Crons, e.Cron)
		}
		return nil
	}
	type plain workflowTrigger
	return n.Decode((*plain)(w))
}

// ghGlob compiles a GitHub Actions path filter: `**` crosses '/', `*` does not.
// The other filter metacharacters (? + [ ]) are refused, not approximated.
func ghGlob(t *testing.T, pat string) *regexp.Regexp {
	t.Helper()
	if strings.ContainsAny(pat, "?+[]") {
		t.Fatalf("path filter %q uses a metacharacter this guard does not model", pat)
	}
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pat); i++ {
		switch {
		case strings.HasPrefix(pat[i:], "**"):
			re.WriteString(".*")
			i++
		case pat[i] == '*':
			re.WriteString("[^/]*")
		default:
			re.WriteString(regexp.QuoteMeta(pat[i : i+1]))
		}
	}
	re.WriteString("$")
	return regexp.MustCompile(re.String())
}

// triggers reports whether a change to file fires a trigger with these paths:
// the last matching pattern wins, and a leading '!' excludes.
func triggers(t *testing.T, paths []string, file string) bool {
	t.Helper()
	hit := false
	for _, p := range paths {
		neg := strings.HasPrefix(p, "!")
		if ghGlob(t, strings.TrimPrefix(p, "!")).MatchString(file) {
			hit = !neg
		}
	}
	return hit
}

// kindWorkflows parses every workflow that runs a `make kind-…` target.
func kindWorkflows(t *testing.T, root string) map[string]workflowFile {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]workflowFile{}
	for _, e := range entries {
		if !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		wf := parseWorkflow(t, e.Name(), b)
		for _, job := range wf.Jobs {
			for _, st := range job.Steps {
				if strings.Contains(st.Run, "make kind-") {
					out[e.Name()] = wf
				}
			}
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "pr.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range parseWorkflow(t, "pr.yaml", b).Jobs {
		name := strings.TrimPrefix(job.Uses, "./.github/workflows/")
		if wf, ok := out[name]; ok {
			wf.CalledByPR = true
			out[name] = wf
		}
	}
	return out
}

func parseWorkflow(t *testing.T, name string, b []byte) workflowFile {
	t.Helper()
	var wf workflowFile
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return wf
}

// uncoveredInputs lists, per trigger, the build-input files a change to which
// would not run the workflow.
func uncoveredInputs(t *testing.T, name string, wf workflowFile, inputs []buildInput) []string {
	t.Helper()
	var out []string
	for _, event := range []string{"push", "pull_request"} {
		trig, ok := wf.On[event]
		if !ok && event == "pull_request" && wf.CalledByPR {
			trig, ok = wf.On["push"] // pr.yaml gates it on these paths
		}
		if !ok {
			out = append(out, name+": has no `"+event+"` trigger")
			continue
		}
		if trig == nil {
			continue // no filter: every path triggers it
		}
		if len(trig.PathsIgnore) > 0 {
			t.Fatalf("%s: %s uses paths-ignore, which this guard does not model", name, event)
		}
		if len(trig.Paths) == 0 {
			continue
		}
		for _, in := range inputs {
			for _, f := range in.files {
				if !triggers(t, trig.Paths, f) {
					out = append(out, name+" on."+event+" misses "+f+"  ("+in.origin+")")
				}
			}
		}
	}
	return out
}

// kindTriggerFixture gathers what both tests below need.
func kindTriggerFixture(t *testing.T) (string, map[string]workflowFile, []buildInput) {
	t.Helper()
	root := repoRoot(t)
	builds := collectDockerBuilds(t, root)
	if len(builds) == 0 {
		t.Fatal("found no `docker build` in deploy/local/*.sh — the collector is broken, not the harness")
	}
	inputs := collectBuildInputs(t, root, trackedFiles(t, root), builds)
	for _, in := range inputs {
		if len(in.files) == 0 {
			t.Fatalf("%s resolved to no tracked file — the collector is broken", in.origin)
		}
	}
	wfs := kindWorkflows(t, root)
	if len(wfs) == 0 {
		t.Fatal("found no workflow running `make kind-…` — the collector is broken")
	}
	return root, wfs, inputs
}

// TestKindWorkflowsTriggerOnEveryImageBuildInput is the guard: every tracked file
// an image in the kind harness is built from must trigger every kind workflow.
func TestKindWorkflowsTriggerOnEveryImageBuildInput(t *testing.T) {
	_, wfs, inputs := kindTriggerFixture(t)
	var missing []string
	for name, wf := range wfs {
		missing = append(missing, uncoveredInputs(t, name, wf, inputs)...)
	}
	slices.Sort(missing)
	missing = slices.Compact(missing)
	if len(missing) > 0 {
		t.Errorf("%d image-build input(s) can change without running the kind workflow that builds "+
			"and deploys them:\n\t%s\n\nAdd a path filter covering each to that workflow's push trigger "+
			"(pr.yaml runs pull requests on the same paths).", len(missing), strings.Join(missing, "\n\t"))
	}
}

// TestKindTriggerGuardCatchesARemovedPath proves the guard is not vacuous on the
// real files: for each build input, deleting from a kind workflow every path
// filter that covers it must make the guard report it.
func TestKindTriggerGuardCatchesARemovedPath(t *testing.T) {
	root, wfs, inputs := kindTriggerFixture(t)
	for name, wf := range wfs {
		raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range inputs {
			probe := in.files[0]
			var kept []string
			removed, pathsIndent := 0, -1
			for _, line := range strings.Split(string(raw), "\n") {
				item := strings.TrimSpace(line)
				indent := len(line) - len(strings.TrimLeft(line, " "))
				switch {
				case item == "paths:":
					pathsIndent = indent
				case pathsIndent >= 0 && indent > pathsIndent && strings.HasPrefix(item, "- "):
					pat := strings.Trim(strings.TrimSpace(strings.TrimPrefix(item, "- ")), `'"`)
					if !strings.HasPrefix(pat, "!") && ghGlob(t, pat).MatchString(probe) {
						removed++
						continue
					}
				case item != "" && !strings.HasPrefix(item, "#"):
					pathsIndent = -1
				}
				kept = append(kept, line)
			}
			if removed == 0 {
				continue // already uncovered; the guard above reports it
			}
			mutated := parseWorkflow(t, name, []byte(strings.Join(kept, "\n")))
			mutated.CalledByPR = wf.CalledByPR
			got := strings.Join(uncoveredInputs(t, name, mutated, []buildInput{{origin: in.origin, files: []string{probe}}}), "\n")
			for _, event := range []string{"push", "pull_request"} {
				if !strings.Contains(got, name+" on."+event+" misses "+probe) {
					t.Errorf("%s with the filter for %s removed: the guard did not report on.%s (got %q)",
						name, probe, event, got)
				}
			}
		}
	}
}
