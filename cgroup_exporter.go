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
	"github.com/containerd/cgroups"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
)

const (
	namespace = "cgroup"
)

var (
	defCgroupRoot          = "/sys/fs/cgroup"
	configPaths            = kingpin.Flag("config.paths", "Comma separated list of cgroup paths to check, eg /user.slice,/system.slice,/slurm").Required().String()
	listenAddress          = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9306").String()
	disableExporterMetrics = kingpin.Flag("web.disable-exporter-metrics", "Exclude metrics about the exporter (promhttp_*, process_*, go_*)").Default("false").Bool()
	cgroupRoot             = kingpin.Flag("path.cgroup.root", "Root path to cgroup fs").Default(defCgroupRoot).String()
	collectFullSlurm       = kingpin.Flag("collect.fullslurm", "Boolean that sets if to collect all slurm steps and tasks").Default("false").Bool()
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
	paths           []string
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

func subsystem() ([]cgroups.Subsystem, error) {
	s := []cgroups.Subsystem{
		cgroups.NewCpuacct(*cgroupRoot),
		cgroups.NewMemory(*cgroupRoot),
	}
	return s, nil
}

func getCPUs(name string, logger log.Logger) ([]string, error) {
	cpusPath := fmt.Sprintf("%s/cpuset%s/cpuset.cpus", *cgroupRoot, name)
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

func getInfo(name string, metric *CgroupMetric, logger log.Logger) {
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
		/*
			user, err := user.LookupId(userSliceMatch[1])
					if err == nil {
					metric.username = user.Username
				} */
		return
	}
	// slurmPattern := regexp.MustCompile("^/slurm/uid_([0-9]+)/job_([0-9]+)(/step_([^/]+)(/task_([[0-9]+))?)?$")
	slurmPattern := regexp.MustCompile(`^/(?:slurm|slurm_[^/]+)/uid_([0-9]+)/job_([0-9]+)(/step_([^/]+)(/task_([[0-9]+))?)?$`)

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
		/*
			user, err := user.LookupId(slurmMatch[1])
				if err == nil {
					metric.username = user.Username
				} */
		return
	}
	if strings.HasPrefix(name, "/torque") {
		metric.job = true
		pathBaseSplit := strings.Split(pathBase, ".")
		metric.jobid = pathBaseSplit[0]
		return
	}
}

func NewExporter(paths []string, logger log.Logger) *Exporter {
	return &Exporter{
		paths: paths,
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
		logger: logger,
	}
}

func (e *Exporter) getMetrics(name string) (CgroupMetric, error) {
	metric := CgroupMetric{name: name}
	metric.err = false
	level.Debug(e.logger).Log("msg", "Loading cgroup", "path", name)
	ctrl, err := cgroups.Load(subsystem, func(subsystem cgroups.Name) (string, error) {
		return name, nil
	})
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to load cgroups", "path", name, "err", err)
		metric.err = true
		return metric, err
	}
	stats, err := ctrl.Stat(cgroups.IgnoreNotExist)
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to stat cgroups", "path", name, "err", err)
		return metric, err
	}
	if stats == nil {
		level.Error(e.logger).Log("msg", "Cgroup stats are nil", "path", name)
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
	if cpus, err := getCPUs(name, e.logger); err == nil {
		metric.cpus = len(cpus)
		metric.cpu_list = strings.Join(cpus, ",")
	}
	getInfo(name, &metric, e.logger)
	return metric, nil
}

func (e *Exporter) collect() (map[string]CgroupMetric, error) {
	var names []string
	var metrics = make(map[string]CgroupMetric)
	topPath := *cgroupRoot + "/cpuacct"
	for _, path := range e.paths {
		level.Debug(e.logger).Log("msg", "Loading cgroup", "path", path)
		err := filepath.Walk(topPath+path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && strings.Contains(p, "/job_") {
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
			level.Error(e.logger).Log("msg", "Error walking cgroup subsystem", "path", path, "err", err)
			//metric := CgroupMetric{name: path, err: true}
			//metrics[path] = metric
			continue
		}
		wg := &sync.WaitGroup{}
		wg.Add(len(names))
		for _, name := range names {
			go func(n string) {
				metric, _ := e.getMetrics(n)
				if !metric.err {
					metricLock.Lock()
					metrics[n] = metric
					metricLock.Unlock()
				}
				wg.Done()
			}(name)
		}
		wg.Wait()
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

func metricsHandler(logger log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()

		paths := strings.Split(*configPaths, ",")

		exporter := NewExporter(paths, logger)
		registry.MustRegister(exporter)
		registry.MustRegister(version.NewCollector(fmt.Sprintf("%s_exporter", namespace)))

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
	http.Handle(metricsEndpoint, metricsHandler(logger))
	err := http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}
