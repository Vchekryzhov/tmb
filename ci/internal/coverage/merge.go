package coverage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Merge adds the counts of every profile block by block: the union of the
// Go-test profile and the integration profile of the harness binaries. The
// modes must match, and a block present in two profiles must have the same
// statement count (same source, same compiler), otherwise the profiles do
// not describe one tree.
func Merge(ps ...Profile) (Profile, error) {
	out := Profile{blocks: map[string]*block{}}
	for i, p := range ps {
		if i == 0 {
			out.Mode = p.Mode
		} else if p.Mode != out.Mode {
			return out, fmt.Errorf("modes differ: %s and %s", out.Mode, p.Mode)
		}
		for k, b := range p.blocks {
			if o, ok := out.blocks[k]; ok {
				if o.stmts != b.stmts {
					return out, fmt.Errorf("block %s: %d statements in one profile, %d in another", k, o.stmts, b.stmts)
				}
				o.count += b.count
				continue
			}
			c := *b
			out.blocks[k] = &c
		}
	}
	if out.Mode == "" {
		return out, fmt.Errorf("nothing to merge")
	}
	return out, nil
}

// Write prints p as a Go cover profile, blocks sorted, so go tool cover reads
// it back.
func (p Profile) Write(w io.Writer) error {
	keys := make([]string, 0, len(p.blocks))
	for k := range p.blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "mode: %s\n", p.Mode)
	for _, k := range keys {
		b := p.blocks[k]
		fmt.Fprintf(bw, "%s %d %d\n", k, b.stmts, b.count)
	}
	return bw.Flush()
}

// OnlyIn counts the statements covered in p but not in other: what the
// integration run adds to the Go tests.
func (p Profile) OnlyIn(other Profile) int {
	n := 0
	for k, b := range p.blocks {
		if b.count == 0 {
			continue
		}
		if o, ok := other.blocks[k]; !ok || o.count == 0 {
			n += b.stmts
		}
	}
	return n
}

// Covdata is what the harness collected per container: Go coverage counter
// files written at process exit (covcounters.<meta hash>.<pid>.<nanotime>)
// and, for broker containers, the journal with broker_start/broker_stop.
type Covdata struct {
	Containers []ContainerCov
	Problems   []string
}

// ContainerCov accounts for one container.
type ContainerCov struct {
	Name     string
	Counters int // counter files, one per process that exited normally
	Brokers  int // broker_start events in the journal
	// Killed are brokers with neither broker_stop nor counters: the process
	// ended without running its exit hooks (SIGKILL, as in N9 or the stop
	// fallback), so its coverage is lost and only listed.
	Killed []int
}

// AccountCovdata reads dir/<container>/covdata and dir/<container>/journal.
// A broker that logged broker_stop exited through main and must have left
// counters; one without them is a problem, not silently dropped coverage.
// No counters at all in a container is a problem too.
func AccountCovdata(dir string) (Covdata, error) {
	var r Covdata
	ents, err := os.ReadDir(dir)
	if err != nil {
		return r, err
	}
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		c := ContainerCov{Name: ent.Name()}
		pids := map[int]bool{}
		files, _ := os.ReadDir(filepath.Join(dir, c.Name, "covdata"))
		for _, f := range files {
			parts := strings.Split(f.Name(), ".")
			if len(parts) != 4 || parts[0] != "covcounters" {
				continue
			}
			c.Counters++
			if pid, err := strconv.Atoi(parts[2]); err == nil {
				pids[pid] = true
			}
		}
		if c.Counters == 0 {
			r.Problems = append(r.Problems, c.Name+": no coverage counters (binaries not built with -cover, or GOCOVERDIR not set)")
		}
		started, stopped, err := journalBrokers(filepath.Join(dir, c.Name, "journal"))
		if err != nil {
			return r, err
		}
		c.Brokers = len(started)
		for _, pid := range started {
			switch {
			case pids[pid]:
			case stopped[pid]:
				r.Problems = append(r.Problems, fmt.Sprintf("%s: broker pid %d logged broker_stop but left no counters", c.Name, pid))
			default:
				c.Killed = append(c.Killed, pid)
			}
		}
		r.Containers = append(r.Containers, c)
	}
	if len(r.Containers) == 0 {
		r.Problems = append(r.Problems, "no container data collected")
	}
	return r, nil
}

// journalBrokers returns the broker_start pids in order and the set of
// broker_stop pids from every journal file in dir (rotated ones included).
// A missing dir is a container without a broker.
func journalBrokers(dir string) ([]int, map[int]bool, error) {
	stopped := map[int]bool{}
	var started []int
	seen := map[int]bool{}
	files, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, stopped, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, f.Name()))
		if err != nil {
			return nil, nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var ev struct {
				Event string `json:"event"`
				PID   int    `json:"pid"`
			}
			if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.PID == 0 {
				continue
			}
			switch ev.Event {
			case "broker_start":
				if !seen[ev.PID] {
					seen[ev.PID] = true
					started = append(started, ev.PID)
				}
			case "broker_stop":
				stopped[ev.PID] = true
			}
		}
		err = sc.Err()
		fh.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	return started, stopped, nil
}
