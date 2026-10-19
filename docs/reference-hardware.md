# Reference hardware (FR-11)

SRS FR-11 requires the CP-32 performance targets to be met "on recorded reference hardware with the reference dataset". The SRS does not name a machine; it asks the project to record one (SRS §1.6, FR-11). This page is that record.

## The recorded reference hardware

The reference hardware is the machine class of the GitHub-hosted standard Linux runner for public repositories with the label `ubuntu-24.04`:

| Property | Value |
|---|---|
| Runner | GitHub-hosted (`RUNNER_ENVIRONMENT=github-hosted`), image `ubuntu24` (Ubuntu 24.04) |
| Architecture | x86_64 (`linux/amd64`) |
| Processors | 4 vCPU |
| Memory | 16 GiB (the kernel reports a `MemTotal` of about 15.6 GiB) |
| Disk | SSD; 14 GB of free space on the root file system is the documented minimum |
| Processor model | Varies by run within the class: AMD EPYC 7763, AMD EPYC 9V74 and Intel Xeon models have been observed |

The CI job `perf` runs on this class (`runs-on: ubuntu-24.04` in `.github/workflows/ci.yml`), and so do the jobs that run the Go tests of FR-11.3, FR-11.7 and FR-11.10 (job `go`).

Because the processor model is not fixed within the class, every performance report records the hardware of its own run. `smcp-workload run` writes into `perf.json` (published as the `performance` member of the status data):

- `host.cpu`, `host.cpus`: the processor model (`/proc/cpuinfo`) and the number of processors;
- `host.memoryBytes`: physical memory (`MemTotal` of `/proc/meminfo`);
- `host.diskBytes`, `host.diskFreeBytes`, `host.diskDevice`, `host.diskModel`: the size and free space of the file system that holds the work directory, its block device and the device's model;
- `host.runnerEnvironment`, `host.image`, `host.imageVersion`: the runner's `RUNNER_ENVIRONMENT`, `ImageOS` and `ImageVersion`;
- `referenceHardware` and `referenceClass`: whether the host matches the class above (`perf.ReferenceClass` in `internal/perf/measure.go`: Linux, amd64, 4 processors, 15 to 17 GiB, GitHub-hosted, image `ubuntu24`).

A run on any other machine is still measured and published, but `referenceHardware` is false and its measurements are partial claims only.

## How the measurements count

`smcp-workload run --test-json` writes each measurement as a test for `tools/reqreport`. A measurement within its budget is:

- a full claim (`VERIFIES`) of its requirement when the run is on the reference hardware and the measurement is complete, that is, it covers the whole verification statement (for example 100,000 decisions for FR-11.2, the 10-minute replay at 2,000 records per second for FR-11.6, the full query set 100 times for FR-11.8);
- a partial claim (`PARTIAL`) otherwise.

A measurement over its budget is a failing test in either case. FR-11.9 is complete only when the graph engine is included: the CI job creates a Neo4j Community Edition container with the CP-33 budget (1 GiB heap, 1 GiB page cache) that `smcp-workload` starts after the FR-11.4 loads (`--graph-container`), the idle instance runs the graph mirror against it, and the sample adds the resident memory of the container's processes to that of `smcpd`. FR-11.6 and FR-11.8 are complete only with the DuckDB Observation Store, the store of the SRS stack (§3.1), which the perf job's binaries (built with cgo) use. The release archives are built without cgo and fall back to the JSON Lines store, which is not measured at this data volume.

## Why this class

The project has one owner and no dedicated benchmark machine. The runner class is a documented, reproducible machine that anyone can rerun the measurements on (dispatch the CI workflow), and it is the platform on which the Enforced profile is qualified (SRS §1.6). Its 16 GiB matches the planning assumption of the architecture (a workstation with at least 16 GiB of memory). Its processors are shared virtual CPUs, so results vary between runs more than on a dedicated machine; each report carries its own hardware record so that results can be compared by processor model.
