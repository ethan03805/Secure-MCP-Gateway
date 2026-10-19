package perf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procRoot is the proc file system treeRSS reads (tests replace it).
var procRoot = "/proc"

// treeRSS returns the combined resident set size of process pid and all
// its descendants, from VmRSS in procRoot/<pid>/status, and the number of
// processes counted. It reads the proc file system, so it works on Linux
// only; the processes of a container on the same host are visible there.
func treeRSS(pid int) (int64, int, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, 0, err
	}
	children := map[int][]int{}
	rss := map[int]int64{}
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "status"))
		if err != nil {
			continue // exited
		}
		var ppid int
		for _, l := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			f := strings.Fields(v)
			if len(f) == 0 {
				continue
			}
			switch k {
			case "PPid":
				ppid, _ = strconv.Atoi(f[0])
			case "VmRSS":
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				rss[p] = kb << 10
			}
		}
		children[ppid] = append(children[ppid], p)
	}
	if _, ok := rss[pid]; !ok {
		if _, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid))); err != nil {
			return 0, 0, errors.New("perf: process " + strconv.Itoa(pid) + " not found")
		}
	}
	var total int64
	n := 0
	stack := []int{pid}
	seen := map[int]bool{}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[p] {
			continue
		}
		seen[p] = true
		total += rss[p]
		n++
		stack = append(stack, children[p]...)
	}
	return total, n, nil
}
