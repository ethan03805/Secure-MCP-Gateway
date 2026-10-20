// Command cfadvisory checks the ContextForge release pinned in the release
// lock against the ContextForge repository's GitHub security advisories
// (SRS FR-22.18: the pinned version has no unfixed advisory of severity
// high or critical on the release date).
//
//	gh api --paginate 'repos/IBM/mcp-context-forge/security-advisories?state=published&per_page=100' > adv.json
//	go run ./tools/cfadvisory -lock packaging/contextforge.lock.json -date 2026-10-20 adv.json
//
// For each published, not withdrawn advisory of severity high or critical
// published on or before the date, the pinned version is fixed when a
// patched version the advisory names is at or below it, and otherwise not
// affected when every vulnerable version range the advisory states can be
// read and excludes it. Any other high or critical advisory is unfixed: the
// command prints it and exits 1. Version strings are read leniently (a
// leading "v", spaces, invisible characters and a package name before the
// range are ignored), and a range that cannot be read counts as affecting
// the pinned version.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type advisory struct {
	GHSA        string `json:"ghsa_id"`
	Severity    string `json:"severity"`
	State       string `json:"state"`
	PublishedAt string `json:"published_at"`
	WithdrawnAt string `json:"withdrawn_at"`
	Summary     string `json:"summary"`
	Vulns       []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Range   string `json:"vulnerable_version_range"`
		Patched string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cfadvisory:", err)
	}
	os.Exit(code)
}

func run(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("cfadvisory", flag.ContinueOnError)
	lockPath := fs.String("lock", "packaging/contextforge.lock.json", "release lock")
	date := fs.String("date", time.Now().UTC().Format("2006-01-02"), "release date (YYYY-MM-DD); later advisories are not counted")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() != 1 {
		return 2, errors.New("one advisories file required")
	}
	day, err := time.Parse("2006-01-02", *date)
	if err != nil {
		return 2, err
	}
	raw, err := os.ReadFile(*lockPath)
	if err != nil {
		return 2, err
	}
	var lock struct {
		ContextForge struct {
			Version string `json:"version"`
		} `json:"contextforge"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return 2, err
	}
	pinned, ok := parseVersion(lock.ContextForge.Version)
	if !ok {
		return 2, fmt.Errorf("lock version %q is not a version", lock.ContextForge.Version)
	}
	advs, err := readAdvisories(fs.Arg(0))
	if err != nil {
		return 2, err
	}
	sort.Slice(advs, func(i, j int) bool { return advs[i].GHSA < advs[j].GHSA })
	fmt.Fprintf(out, "ContextForge %s against %d published advisories on %s\n", lock.ContextForge.Version, len(advs), *date)
	unfixed := 0
	for _, a := range advs {
		sev := strings.ToLower(a.Severity)
		if sev != "high" && sev != "critical" {
			continue
		}
		if a.State != "" && a.State != "published" || a.WithdrawnAt != "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, a.PublishedAt); err == nil && t.After(day.Add(24*time.Hour)) {
			continue
		}
		verdict, fixed := judge(a, pinned)
		mark := "ok"
		if !fixed {
			mark = "UNFIXED"
			unfixed++
		}
		fmt.Fprintf(out, "%s %s %s: %s\n", mark, a.GHSA, sev, verdict)
	}
	if unfixed > 0 {
		return 1, fmt.Errorf("%d high or critical advisories affect ContextForge %s", unfixed, lock.ContextForge.Version)
	}
	fmt.Fprintf(out, "no unfixed high or critical advisory affects ContextForge %s\n", lock.ContextForge.Version)
	return 0, nil
}

// readAdvisories reads one JSON array, or several in a row (gh api
// --paginate prints one per page).
func readAdvisories(path string) ([]advisory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var all []advisory
	for {
		var page []advisory
		if err := dec.Decode(&page); errors.Is(err, io.EOF) {
			return all, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, page...)
	}
}

// judge reports why the pinned version is or is not affected.
func judge(a advisory, pinned version) (string, bool) {
	if len(a.Vulns) == 0 {
		return "names no vulnerable versions", false
	}
	var notes []string
	for _, v := range a.Vulns {
		var patched []version
		for _, s := range versionRE.FindAllString(clean(v.Patched), -1) {
			if p, ok := parseVersion(s); ok {
				patched = append(patched, p)
			}
		}
		sort.Slice(patched, func(i, j int) bool { return patched[i].less(patched[j]) })
		if len(patched) > 0 && !pinned.less(patched[0]) {
			notes = append(notes, fmt.Sprintf("fixed in %s", patched[0]))
			continue
		}
		in, ok := inRange(clean(v.Range), pinned)
		if !ok {
			return fmt.Sprintf("vulnerable range %q cannot be read and no patched version at or below %s", v.Range, pinned), false
		}
		if in {
			return fmt.Sprintf("vulnerable range %q includes %s", v.Range, pinned), false
		}
		notes = append(notes, fmt.Sprintf("range %q excludes it", v.Range))
	}
	return strings.Join(notes, "; "), true
}

var versionRE = regexp.MustCompile(`v?\d+\.\d+(\.\d+)?(-[0-9A-Za-z.]+)?`)

// clean removes invisible characters and a package name before a range.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == 0x2060 || r == 0x200b || r == 0xfeff || r == 0x00a0 {
			return -1
		}
		return r
	}, s)
	if i := strings.IndexAny(s, "<>=0123456789v"); i > 0 && !strings.ContainsAny(s[:i], "<>=") {
		s = s[i:]
	}
	return strings.TrimSpace(s)
}

type version struct {
	n   [3]int
	pre string
}

func (v version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.n[0], v.n[1], v.n[2])
	if v.pre != "" {
		s += "-" + v.pre
	}
	return s
}

func (v version) less(w version) bool {
	for i := range 3 {
		if v.n[i] != w.n[i] {
			return v.n[i] < w.n[i]
		}
	}
	if v.pre == w.pre {
		return false
	}
	if v.pre == "" {
		return false
	}
	if w.pre == "" {
		return true
	}
	return strings.ToLower(v.pre) < strings.ToLower(w.pre)
}

func parseVersion(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return version{}, false
	}
	var v version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return version{}, false
		}
		v.n[i] = n
	}
	v.pre = pre
	return v, true
}

// inRange evaluates a range such as "< 1.0.7", "<= 1.0.6", ">= 1.0.0,
// < 1.0.11" or a single version. ok is false when it cannot be read.
func inRange(r string, v version) (in, ok bool) {
	if r == "" {
		return false, false
	}
	in = true
	for _, c := range strings.Split(r, ",") {
		c = strings.TrimSpace(c)
		op := ""
		for _, o := range []string{"<=", ">=", "<", ">", "="} {
			if strings.HasPrefix(c, o) {
				op, c = o, strings.TrimSpace(c[len(o):])
				break
			}
		}
		w, ok := parseVersion(c)
		if !ok {
			return false, false
		}
		var hold bool
		switch op {
		case "<":
			hold = v.less(w)
		case "<=":
			hold = !w.less(v)
		case ">":
			hold = w.less(v)
		case ">=":
			hold = !v.less(w)
		default:
			hold = !v.less(w) && !w.less(v)
		}
		in = in && hold
	}
	return in, true
}
