// Copyright 2020 Trey Dockendorf
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/alecthomas/kingpin/v2"
	"github.com/containerd/cgroups/v3/cgroup1"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"golang.org/x/sys/unix"
)

const (
	namespace = "cgroup"
)

var (
	defCgroupRoot          = "/sys/fs/cgroup"
	listenAddress          = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9306").String()
	disableExporterMetrics = kingpin.Flag("web.disable-exporter-metrics", "Exclude metrics about the exporter (promhttp_*, process_*, go_*)").Default("false").Bool()
	cgroupRoot             = kingpin.Flag("path.cgroup.root", "Root path to cgroup fs").Default(defCgroupRoot).String()
	collectFullSlurm       = kingpin.Flag("collect.fullslurm", "Boolean that sets if to collect all slurm steps and tasks").Default("false").Bool()
	cgroupV2               = false
	metricLock             = sync.RWMutex{}
)

type CgroupMetric struct {
	name            string
	cpuUser         float64
	cpuSystem       float64
	cpuTotal        float64
	cpus            int
	cpu_list        string
	memoryRSS       float64
	memoryCache     float64
	memoryUsed      float64
	memoryTotal     float64
	memoryFailCount float64
	memswUsed       float64
	memswTotal      float64
	memswFailCount  float64
	userslice       bool
	job             bool
	uid             int
	//	username        string
	jobid string
	step  string
	task  string
	err   bool
}

type Exporter struct {
	uid             *prometheus.Desc
	collectError    *prometheus.Desc
	cpuUser         *prometheus.Desc
	cpuSystem       *prometheus.Desc
	cpuTotal        *prometheus.Desc
	cpus            *prometheus.Desc
	cpu_info        *prometheus.Desc
	memoryRSS       *prometheus.Desc
	memoryCache     *prometheus.Desc
	memoryUsed      *prometheus.Desc
	memoryTotal     *prometheus.Desc
	memoryFailCount *prometheus.Desc
	memswUsed       *prometheus.Desc
	memswTotal      *prometheus.Desc
	memswFailCount  *prometheus.Desc
	info            *prometheus.Desc
	logger          log.Logger
	getMetrics      func(log.Logger, string) (CgroupMetric, error)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func sliceContains(s interface{}, v interface{}) bool {
	slice := reflect.ValueOf(s)
	for i := 0; i < slice.Len(); i++ {
		if slice.Index(i).Interface() == v {
			return true
		}
	}
	return false
}

func subsystem() ([]cgroup1.Subsystem, error) {
	s := []cgroup1.Subsystem{
		cgroup1.NewCpuacct(*cgroupRoot),
		cgroup1.NewMemory(*cgroupRoot),
	}
	return s, nil
}

func getCPUs(name string, cgroupV2 bool, logger log.Logger) ([]string, error) {
	var cpusPath string
	if cgroupV2 {
		cpusPath = fmt.Sprintf("%s%s/cpuset.cpus.effective", *cgroupRoot, name)
	} else {
		cpusPath = fmt.Sprintf("%s/cpuset%s/cpuset.cpus", *cgroupRoot, name)
	}
	if !fileExists(cpusPath) {
		return nil, nil
	}
	cpusData, err := os.ReadFile(cpusPath)
	if err != nil {
		level.Error(logger).Log("msg", "Error reading cpuset", "cpuset", cpusPath, "err", err)
		return nil, err
	}
	cpus, err := parseCpuSet(strings.TrimSuffix(string(cpusData), "\n"))
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing cpu set", "cpuset", cpusPath, "err", err)
		return nil, err
	}
	return cpus, nil
}

func parseCpuSet(cpuset string) ([]string, error) {
	var cpus []string
	var start, end int
	var err error
	if cpuset == "" {
		return nil, nil
	}
	ranges := strings.Split(cpuset, ",")
	for _, r := range ranges {
		boundaries := strings.Split(r, "-")
		if len(boundaries) == 1 {
			start, err = strconv.Atoi(boundaries[0])
			if err != nil {
				return nil, err
			}
			end = start
		} else if len(boundaries) == 2 {
			start, err = strconv.Atoi(boundaries[0])
			if err != nil {
				return nil, err
			}
			end, err = strconv.Atoi(boundaries[1])
			if err != nil {
				return nil, err
			}
		}
		for e := start; e <= end; e++ {
			cpu := strconv.Itoa(e)
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}

func getInfoV1(name string, metric *CgroupMetric, logger log.Logger) {
	var err error
	pathBase := filepath.Base(name)
	userSlicePattern := regexp.MustCompile("^user-([0-9]+).slice$")
	userSliceMatch := userSlicePattern.FindStringSubmatch(pathBase)
	if len(userSliceMatch) == 2 {
		metric.userslice = true
		metric.uid, err = strconv.Atoi(userSliceMatch[1])
		if err != nil {
			level.Error(logger).Log("msg", "Error getting slurm uid number", "uid", pathBase, "err", err)
		}
		return
	}
	slurmPattern := regexp.MustCompile("^/slurm/uid_([0-9]+)/job_([0-9]+)(/step_([^/]+)(/task_([[0-9]+))?)?$")
	slurmMatch := slurmPattern.FindStringSubmatch(name)
	level.Debug(logger).Log("msg", "Got for match", "name", name, "len(slurmMatch)", len(slurmMatch), "slurmMatch", fmt.Sprintf("%v", slurmMatch))
	if len(slurmMatch) >= 3 {
		metric.job = true
		metric.uid, err = strconv.Atoi(slurmMatch[1])
		if err != nil {
			level.Error(logger).Log("msg", "Error getting slurm uid number", "uid", name, "err", err)
		}
		metric.jobid = slurmMatch[2]
		metric.step = slurmMatch[4]
		metric.task = slurmMatch[6]
		return
	}
}

func getInfoV2(name string, metric *CgroupMetric, logger log.Logger) {
	// possibilities are /system.slice/slurmstepd.scope/job_211
	//                   /system.slice/slurmstepd.scope/job_211/step_interactive
	//                   /system.slice/slurmstepd.scope/job_211/step_extern/user/task_0
	// we never ever get the uid
	metric.uid = -1
	// nor is there a userslice
	metric.userslice = false
	slurmPattern := regexp.MustCompile("^/system.slice/slurmstepd.scope/job_([0-9]+)(/step_([^/]+)(/user/task_([[0-9]+))?)?$")
	slurmMatch := slurmPattern.FindStringSubmatch(name)
	level.Debug(logger).Log("msg", "Got for match", "name", name, "len(slurmMatch)", len(slurmMatch), "slurmMatch", fmt.Sprintf("%v", slurmMatch))
	if len(slurmMatch) == 6 {
		metric.job = true
		metric.jobid = slurmMatch[1]
		metric.step = slurmMatch[3]
		metric.task = slurmMatch[5]
	}
}

func NewExporter(logger log.Logger, getMetrics func(log.Logger, string) (CgroupMetric, error)) *Exporter {
	return &Exporter{
		uid: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "uid"),
			"Uid number of user running this job", []string{"jobid"}, nil),
		cpuUser: prometheus.NewDesc(prometheus.BuildFQName(namespace, "cpu", "user_seconds"),
			"Cumulative CPU user seconds for jobid", []string{"jobid", "step", "task"}, nil),
		cpuSystem: prometheus.NewDesc(prometheus.BuildFQName(namespace, "cpu", "system_seconds"),
			"Cumulative CPU system seconds for jobid", []string{"jobid", "step", "task"}, nil),
		cpuTotal: prometheus.NewDesc(prometheus.BuildFQName(namespace, "cpu", "total_seconds"),
			"Cumulative CPU total seconds for jobid", []string{"jobid", "step", "task"}, nil),
		cpus: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "cpus"),
			"Number of CPUs in the jobid", []string{"jobid", "step", "task"}, nil),
		cpu_info: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "cpu_info"),
			"Information about the jobid CPUs", []string{"jobid", "cpus", "step", "task"}, nil),
		memoryRSS: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memory", "rss_bytes"),
			"Memory RSS used in bytes", []string{"jobid", "step", "task"}, nil),
		memoryCache: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memory", "cache_bytes"),
			"Memory cache used in bytes", []string{"jobid", "step", "task"}, nil),
		memoryUsed: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memory", "used_bytes"),
			"Memory used in bytes", []string{"jobid", "step", "task"}, nil),
		memoryTotal: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memory", "total_bytes"),
			"Memory total given to jobid in bytes", []string{"jobid", "step", "task"}, nil),
		memoryFailCount: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memory", "fail_count"),
			"Memory fail count", []string{"jobid", "step", "task"}, nil),
		memswUsed: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memsw", "used_bytes"),
			"Swap used in bytes", []string{"jobid", "step", "task"}, nil),
		memswTotal: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memsw", "total_bytes"),
			"Swap total given to jobid in bytes", []string{"jobid", "step", "task"}, nil),
		memswFailCount: prometheus.NewDesc(prometheus.BuildFQName(namespace, "memsw", "fail_count"),
			"Swap fail count", []string{"jobid", "step", "task"}, nil),
		collectError: prometheus.NewDesc(prometheus.BuildFQName(namespace, "exporter", "collect_error"),
			"Indicates collection error, 0=no error, 1=error", []string{"jobid", "step", "task"}, nil),
		logger:     logger,
		getMetrics: getMetrics,
	}
}

func getMetricsV1(logger log.Logger, name string) (CgroupMetric, error) {
	metric := CgroupMetric{name: name}
	metric.err = false
	level.Debug(logger).Log("msg", "Loading cgroup v1", "path", name)
	ctrl, err := cgroup1.Load(cgroup1.StaticPath(name), cgroup1.WithHiearchy(subsystem))
	if err != nil {
		level.Error(logger).Log("msg", "Failed to load cgroups", "path", name, "err", err)
		metric.err = true
		return metric, err
	}
	stats, err := ctrl.Stat(cgroup1.IgnoreNotExist)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to stat cgroups", "path", name, "err", err)
		return metric, err
	}
	if stats == nil {
		level.Error(logger).Log("msg", "Cgroup stats are nil", "path", name)
		return metric, err
	}
	if stats.CPU != nil {
		if stats.CPU.Usage != nil {
			metric.cpuUser = float64(stats.CPU.Usage.User) / 1000000000.0
			metric.cpuSystem = float64(stats.CPU.Usage.Kernel) / 1000000000.0
			metric.cpuTotal = float64(stats.CPU.Usage.Total) / 1000000000.0
		}
	}
	if stats.Memory != nil {
		metric.memoryRSS = float64(stats.Memory.TotalRSS)
		metric.memoryCache = float64(stats.Memory.TotalCache)
		if stats.Memory.Usage != nil {
			metric.memoryUsed = float64(stats.Memory.Usage.Usage)
			metric.memoryTotal = float64(stats.Memory.Usage.Limit)
			metric.memoryFailCount = float64(stats.Memory.Usage.Failcnt)
		}
		if stats.Memory.Swap != nil {
			metric.memswUsed = float64(stats.Memory.Swap.Usage)
			metric.memswTotal = float64(stats.Memory.Swap.Limit)
			metric.memswFailCount = float64(stats.Memory.Swap.Failcnt)
		}
	}
	if cpus, err := getCPUs(name, false, logger); err == nil {
		metric.cpus = len(cpus)
		metric.cpu_list = strings.Join(cpus, ",")
	}
	getInfoV1(name, &metric, logger)
	return metric, nil
}

func LoadAllV2Metrics(name string) (map[string]float64, error) {
	data := make(map[string]float64)
	// Files to parse out of the cgroup
	dataFetch := []string{"cpu.stat", "memory.current", "memory.events", "memory.max", "memory.stat"}

	for _, fName := range dataFetch {
		contents, err := os.ReadFile(filepath.Join(*cgroupRoot, name, fName))
		if err != nil {
			return data, err
		}
		for _, line := range strings.Split(string(contents), "\n") {
			// Some of the above have a single value and others have a "data_name 123"
			parts := strings.Fields(line)
			indName := fName
			indData := 0
			if len(parts) == 1 || len(parts) == 2 {
				if len(parts) == 2 {
					indName += "." + parts[0]
					indData = 1
				}
				if parts[indData] == "max" {
					data[indName] = -1.0
				} else {
					f, err := strconv.ParseFloat(parts[indData], 64)
					if err == nil {
						data[indName] = f
					} else {
						return data, err
					}
				}
			}
		}
	}
	return data, nil
}

// Convenience function that will check if name+metric exists in the data
// and log an error if it does not. It returns 0 in such case but otherwise
// returns the value
func getOneMetric(logger log.Logger, name string, metric string, required bool, data map[string]float64) float64 {
	val, ok := data[metric]
	if !ok && required {
		level.Error(logger).Log("msg", "Failed to load", "metric", metric, "cgroup", name)
	}
	return val
}

func getMetricsV2(logger log.Logger, name string) (CgroupMetric, error) {
	metric := CgroupMetric{name: name}
	metric.err = false
	level.Debug(logger).Log("msg", "Loading cgroup v2", "path", name)
	data, err := LoadAllV2Metrics(name)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to load cgroups", "path", name, "err", err)
		metric.err = true
		return metric, err
	}
	metric.cpuUser = getOneMetric(logger, name, "cpu.stat.user_usec", true, data) / 1000000.0
	metric.cpuSystem = getOneMetric(logger, name, "cpu.stat.system_usec", true, data) / 1000000.0
	metric.cpuTotal = getOneMetric(logger, name, "cpu.stat.usage_usec", true, data) / 1000000.0
	// we use Oom entry from memory.events - it maps most closely to FailCount
	// TODO: add oom_kill as a separate value
	metric.memoryFailCount = getOneMetric(logger, name, "memory.events.oom", true, data)
	// taking Slurm's cgroup v2 as inspiration, swapcached could be missing if swap is off so OK to ignore that case
	metric.memoryRSS = getOneMetric(logger, name, "memory.stat.anon", true, data) + getOneMetric(logger, name, "memory.stat.swapcached", false, data)
	// I guess?
	metric.memoryCache = getOneMetric(logger, name, "memory.stat.file", true, data)
	metric.memoryUsed = getOneMetric(logger, name, "memory.current", true, data)
	metric.memoryTotal = getOneMetric(logger, name, "memory.max", true, data)
	metric.memswUsed = 0.0
	metric.memswTotal = 0.0
	metric.memswFailCount = 0.0
	if cpus, err := getCPUs(name, true, logger); err == nil {
		metric.cpus = len(cpus)
		metric.cpu_list = strings.Join(cpus, ",")
	}
	getInfoV2(name, &metric, logger)
	return metric, nil
}

func (e *Exporter) collect() (map[string]CgroupMetric, error) {
	var names []string
	var metrics = make(map[string]CgroupMetric)
	var topPath string
	var fullPath string
	if cgroupV2 {
		topPath = *cgroupRoot
		fullPath = topPath + "/system.slice/slurmstepd.scope"
	} else {
		topPath = *cgroupRoot + "/cpuacct"
		fullPath = topPath + "/slurm"
	}
	level.Debug(e.logger).Log("msg", "Loading cgroup", "path", fullPath)
	err := filepath.Walk(fullPath, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && strings.Contains(p, "/job_") && !strings.HasSuffix(p, "/slurm") && !strings.HasSuffix(p, "/user") {
			if !*collectFullSlurm && strings.Contains(p, "/step_") {
				return nil
			}
			rel, _ := filepath.Rel(topPath, p)
			level.Debug(e.logger).Log("msg", "Get Name", "name", p, "rel", rel)
			names = append(names, "/"+rel)
		}
		return nil
	})
	if err != nil {
		level.Error(e.logger).Log("msg", "Error walking cgroup subsystem", "path", fullPath, "err", err)
		return metrics, nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(names))
	for _, name := range names {
		go func(n string) {
			metric, _ := e.getMetrics(e.logger, n)
			if !metric.err {
				metricLock.Lock()
				metrics[n] = metric
				metricLock.Unlock()
			}
			wg.Done()
		}(name)
	}
	wg.Wait()
	// if memory.max = "max" case we set memory max to -1
	// fix it by looking at the parent
	// we loop through names once as it was the result of Walk so top paths are seen first
	// also some cgroups we ignore, like path=/system.slice/slurmstepd.scope/job_216/step_interactive/user, hence the need to loop through multiple parents
	if cgroupV2 {
		for _, name := range names {
			metric, ok := metrics[name]
			if ok && metric.memoryTotal < 0 {
				for upName := name; len(upName) > 1; {
					upName = filepath.Dir(upName)
					upMetric, ok := metrics[upName]
					if ok {
						metric.memoryTotal = upMetric.memoryTotal
						metrics[name] = metric
					}
				}
			}
		}
	}
	return metrics, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.cpuUser
	ch <- e.cpuSystem
	ch <- e.cpuTotal
	ch <- e.cpus
	ch <- e.cpu_info
	ch <- e.memoryRSS
	ch <- e.memoryCache
	ch <- e.memoryUsed
	ch <- e.memoryTotal
	ch <- e.memoryFailCount
	ch <- e.memswUsed
	ch <- e.memswTotal
	ch <- e.memswFailCount
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	metrics, _ := e.collect()
	for n, m := range metrics {
		if m.err {
			ch <- prometheus.MustNewConstMetric(e.collectError, prometheus.GaugeValue, 1, m.name)
		}
		if m.step == "" && m.task == "" {
			ch <- prometheus.MustNewConstMetric(e.uid, prometheus.GaugeValue, float64(m.uid), m.jobid)
		}
		ch <- prometheus.MustNewConstMetric(e.cpuUser, prometheus.GaugeValue, m.cpuUser, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.cpuSystem, prometheus.GaugeValue, m.cpuSystem, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.cpuTotal, prometheus.GaugeValue, m.cpuTotal, m.jobid, m.step, m.task)
		cpus := m.cpus
		if cpus == 0 {
			dir := filepath.Dir(n)
			cpus = metrics[dir].cpus
			if cpus == 0 {
				cpus = metrics[filepath.Dir(dir)].cpus
			}
		}
		ch <- prometheus.MustNewConstMetric(e.cpus, prometheus.GaugeValue, float64(cpus), m.jobid, m.step, m.task)
		//ch <- prometheus.MustNewConstMetric(e.cpu_info, prometheus.GaugeValue, 1, m.name, m.cpu_list, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memoryRSS, prometheus.GaugeValue, m.memoryRSS, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memoryCache, prometheus.GaugeValue, m.memoryCache, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memoryUsed, prometheus.GaugeValue, m.memoryUsed, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memoryTotal, prometheus.GaugeValue, m.memoryTotal, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memoryFailCount, prometheus.GaugeValue, m.memoryFailCount, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memswUsed, prometheus.GaugeValue, m.memswUsed, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memswTotal, prometheus.GaugeValue, m.memswTotal, m.jobid, m.step, m.task)
		ch <- prometheus.MustNewConstMetric(e.memswFailCount, prometheus.GaugeValue, m.memswFailCount, m.jobid, m.step, m.task)
	}
}

func metricsHandler(cgroupV2 bool, logger log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()

		//exporter := NewExporter(logger, getMetricsV1)
		if cgroupV2 {
			registry.MustRegister(NewExporter(logger, getMetricsV2))
		} else {
			registry.MustRegister(NewExporter(logger, getMetricsV1))
		}
		// registry.MustRegister(version.NewCollector(fmt.Sprintf("%s_exporter", namespace)))

		gatherers := prometheus.Gatherers{registry}
		if !*disableExporterMetrics {
			gatherers = append(gatherers, prometheus.DefaultGatherer)
		}

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

func main() {
	metricsEndpoint := "/metrics"
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("cgroup_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := promlog.New(promlogConfig)
	level.Info(logger).Log("msg", "Starting cgroup_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	var st unix.Statfs_t
	if err := unix.Statfs(*cgroupRoot, &st); err == nil {
		if st.Type == unix.CGROUP2_SUPER_MAGIC {
			cgroupV2 = true
			level.Info(logger).Log("msg", "Cgroup version v2 detected on ", "mount", cgroupRoot)
		} else {
			level.Info(logger).Log("msg", "Cgroup version v2 not detected, will proceed with v1.")
		}
	} else {
		level.Error(logger).Log("Failed to check type of cgroup used with error", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Starting Server", "address", *listenAddress)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		w.Write([]byte(`<html>
             <head><title>cgroup Exporter</title></head>
             <body>
             <h1>cgroup Exporter</h1>
             <p><a href='` + metricsEndpoint + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	http.Handle(metricsEndpoint, metricsHandler(cgroupV2, logger))
	err := http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}
