package ciguard

// ── WHY THIS EXISTS (B28.199) ────────────────────────────────────────────────
//
// Every workflow here is path-filtered, so a check runs only when a file it names
// changes. What drifts without a commit — a base image, a manifest a kind phase
// fetches by URL, a registry that stops serving a pinned tag — stays unseen until
// some unrelated change trips over it. A `schedule:` runs each workflow against
// main every night; this fails if a workflow has none.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// allWorkflows parses every file in .github/workflows.
func allWorkflows(t *testing.T, root string) map[string][]byte {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = b
	}
	if len(out) == 0 {
		t.Fatal("found no workflow in .github/workflows — the collector is broken")
	}
	return out
}

// scheduleProblem says why a workflow does not run nightly, or "" if it does.
func scheduleProblem(name string, wf workflowFile) string {
	trig := wf.On["schedule"]
	if trig == nil || len(trig.Crons) == 0 {
		return name + ": no `on.schedule` cron"
	}
	for _, c := range trig.Crons {
		if len(strings.Fields(c)) != 5 {
			return name + ": schedule cron `" + c + "` is not five fields"
		}
	}
	return ""
}

func TestEveryWorkflowRunsNightly(t *testing.T) {
	var bad []string
	for name, raw := range allWorkflows(t, repoRoot(t)) {
		if name == "pr.yaml" {
			continue // runs only on pull requests; every workflow it calls runs nightly itself (B33.2)
		}
		if p := scheduleProblem(name, parseWorkflow(t, name, raw)); p != "" {
			bad = append(bad, p)
		}
	}
	slices.Sort(bad)
	if len(bad) > 0 {
		t.Errorf("%d workflow(s) never run on main unless a filtered path changes:\n\t%s\n\n"+
			"Add `schedule: [{cron: '17 3 * * *'}]` under `on:`.", len(bad), strings.Join(bad, "\n\t"))
	}
}

// TestNightlyGuardCatchesARemovedSchedule proves the guard is not vacuous on the
// real files: each workflow with its `schedule:` block cut out must be reported.
func TestNightlyGuardCatchesARemovedSchedule(t *testing.T) {
	for name, raw := range allWorkflows(t, repoRoot(t)) {
		var kept []string
		cut, blockIndent := false, -1
		for _, line := range strings.Split(string(raw), "\n") {
			item := strings.TrimSpace(line)
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if blockIndent >= 0 && (item == "" || indent > blockIndent) {
				continue
			}
			blockIndent = -1
			if item == "schedule:" {
				cut, blockIndent = true, indent
				continue
			}
			kept = append(kept, line)
		}
		if !cut {
			continue // no schedule to remove; TestEveryWorkflowRunsNightly reports it
		}
		if scheduleProblem(name, parseWorkflow(t, name, []byte(strings.Join(kept, "\n")))) == "" {
			t.Errorf("%s with its schedule removed: the guard reported nothing", name)
		}
	}
}
