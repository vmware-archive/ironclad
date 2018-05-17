// Copyright © 2018 Heptio
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/heptiolabs/healthcheck"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/heptiolabs/ironclad/pkg/audit"
	"github.com/heptiolabs/ironclad/pkg/buildinfo"
	"github.com/heptiolabs/ironclad/pkg/nginx"
)

// configChangeDebounceTime sets the amount of time we'll wait after seeing a
// config file change before acting on the change. If other filesystem change
// events happen during this time, the timer will reset and the configuration
// change will only be processed once.
const configChangeDebounceTime = 100 * time.Millisecond

// variables which are set via CLI flags
var (
	configPath       string
	metricsPort      uint16
	metricsNamespace string
	healthPort       uint16
)

// IroncladCmd represents the base command when called without any subcommands
var IroncladCmd = &cobra.Command{
	Use:     "ironclad",
	Short:   "Nginx+ModSecurity for Kubernetes",
	Long:    "A sidecar that integrates nginx and ModSecurity with Kubernetes",
	PreRunE: validate,
	Run:     run,
}

// validate command line flags
func validate(_ *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("unexpected arguments: %v", args[1:])
	}

	// load configuration file
	if configPath != "" {
		viper.SetConfigFile(configPath)
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
	}

	// validate configuration (from file and CLI flags)
	if err := viperValidate(); err != nil {
		return err
	}
	return nil
}

// run the server
func run(_ *cobra.Command, _ []string) {
	reconfigureLogrus()
	logrus.WithFields(logrus.Fields{
		"version":   buildinfo.Version,
		"buildTime": buildinfo.BuildTime,
	}).Info("starting ironclad")

	// create a metrics registry
	metricsRegistry := prometheus.NewRegistry()

	// register our own process-level metrics
	processStats := prometheus.NewProcessCollector(os.Getpid(), metricsNamespace)
	if err := metricsRegistry.Register(processStats); err != nil {
		logrus.WithError(err).Fatal("failed to register process metrics")
	}

	// register our own Go runtime metrics
	if err := metricsRegistry.Register(prometheus.NewGoCollector()); err != nil {
		logrus.WithError(err).Fatal("failed to register runtime metrics")
	}

	// create a healthcheck handler that also ships metrics
	health := healthcheck.NewMetricsHandler(metricsRegistry, "ironclad")
	backendAddr := fmt.Sprintf("127.0.0.1:%d", viper.GetInt("backendPort"))

	//
	health.AddReadinessCheck(
		"backend-tcp-connect",
		healthcheck.TCPDialCheck(backendAddr, 50*time.Millisecond))

	// if there's a health port set, expose health
	if healthPort != 0 {
		healthListen := fmt.Sprintf("0.0.0.0:%d", healthPort)
		go http.ListenAndServe(healthListen, health)
	}

	// if a --metrics-port is set, serve metrics over HTTP
	if metricsPort != 0 {
		// start an HTTP listener on metricsPort serving Prometheus at /metrics
		metricsListen := fmt.Sprintf("0.0.0.0:%d", metricsPort)
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{}))
		go http.ListenAndServe(metricsListen, mux)
		logrus.WithField("listen", metricsListen).Info("started metrics listener")
	}

	// start a background HTTP server to receive audit events
	auditServer, err := audit.StartServer()
	if err != nil {
		logrus.WithError(err).Fatal("could not start audit event listener")
	}

	// attach a logging handler that annotates with pod metadata and GeoIP lookups
	auditServer.AddHandler(audit.NewLoggerHandler(logrus.StandardLogger()))

	// attach a MetricsHandler that measures various attributes of audit events
	metricsHandler, err := audit.NewMetricsHandler(metricsRegistry, metricsNamespace)
	if err != nil {
		logrus.WithError(err).Fatal("could not create metrics handler")
	}
	auditServer.AddHandler(metricsHandler)

	// launch nginx as a subprocess
	nginxServer, err := nginx.Start(
		viperNginxConfig(auditServer.URL()),
		metricsRegistry,
		metricsNamespace)
	if err != nil {
		logrus.WithError(err).Fatal("could not start nginx")
	}

	// if nginx exits, exit with an error
	go func() {
		logrus.WithError(nginxServer.WaitForExit()).Fatal("nginx exited")
	}()

	// if there is a configuration file, then reload whenever it changes
	if configPath != "" {

		// create a timer for when we'll reload nginx, then immediately consume its first event
		reloadTimer := time.NewTimer(0)
		<-reloadTimer.C

		// Whenever we see a config change, reset the timer to fire after
		// configChangeDebounceTime. This debounces filesystem change events
		// so a quick burst of changes gets consolidated into a single reload.
		logrus.WithField("path", configPath).Info("watching configuration")
		watchConfigChange(func(fsnotify.Event) {
			reloadTimer.Reset(configChangeDebounceTime)
		})

		// every time the timer fires, reload nginx
		for range reloadTimer.C {
			logrus.Debug("loading fresh config")
			if err := viper.ReadInConfig(); err != nil {
				logrus.WithError(err).Error("could not load configuration")
				continue
			}
			if err := viperValidate(); err != nil {
				logrus.WithError(err).Error("invalid configuration")
				continue
			}
			reconfigureLogrus()
			nginxServer.Reload(viperNginxConfig(auditServer.URL()))
		}
	}
}

// TODO: drop this once https://github.com/spf13/viper/issues/284 is fixed
// this assumes that the configPath is in a directory loaded via Kubernetes ConfigMap,
// which uses some tricks with symlinks to make multi-file updates atomic
func watchConfigChange(onChange func(fsnotify.Event)) {
	// if ..data doesn't exist, assume we're dealing with a normal file
	if _, err := os.Stat(filepath.Join(filepath.Dir(configPath), "..data")); err != nil {
		viper.WatchConfig()
		viper.OnConfigChange(onChange)
		return
	}

	// otherwise, set up our own fsnotify watcher on the parent directory
	// and watch for ..data to be (re)created
	logrus.Debug("using Kubernetes ConfigMap-specific watcher implementation")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.WithError(err).Fatal("could not create watcher")
	}
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Create != fsnotify.Create {
					continue
				}
				if filepath.Base(event.Name) != "..data" {
					continue
				}
				onChange(event)
			case err := <-watcher.Errors:
				logrus.WithError(err).Fatal("error watching filesystem events")
			}
		}
	}()
	watcher.Add(filepath.Dir(configPath))
}

// reconfigureLogrus sets up logrus to write to stdout in the chosen format/level
func reconfigureLogrus() {
	logrus.SetOutput(os.Stdout)

	if level, err := logrus.ParseLevel(viper.GetString("logLevel")); err == nil {
		logrus.SetLevel(level)
	}

	switch viper.GetString("logFormat") {
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
}

func viperValidate() error {
	for _, subnet := range viper.GetStringSlice("trustedProxyIPRanges") {
		_, _, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("invalid IP range %q, should be specified like \"x.y.z.w/q\"", subnet)
		}
	}

	switch viper.GetString("logFormat") {
	case "text":
	case "json":
	default:
		return fmt.Errorf("invalid log format (must be \"text\" or \"json\")")
	}

	if _, err := logrus.ParseLevel(viper.GetString("logLevel")); err != nil {
		return fmt.Errorf("invalid log level (must be one of %v)", logrus.AllLevels)
	}

	return nil
}

func viperNginxConfig(auditReceiverURL string) nginx.Config {
	return nginx.Config{
		ListenPort:           uint16(viper.GetInt("listenPort")),
		BackendPort:          uint16(viper.GetInt("backendPort")),
		TrustedProxyIPRanges: viper.GetStringSlice("trustedProxyIPRanges"),
		AuditReceiverURL:     auditReceiverURL,
		DetectionOnly:        viper.GetBool("detectionOnly"),
		PrependedRules:       viper.GetStringSlice("prependRules"),
		AppendedRules:        viper.GetStringSlice("appendRules"),
	}
}

func main() {
	// --config (only settable via flag, no configuration file field)
	IroncladCmd.Flags().StringVarP(&configPath, "config", "c", "", "Configuration file path")

	// --metrics-port (only settable via flag, no configuration file field)
	IroncladCmd.Flags().Uint16Var(&metricsPort, "metrics-port", 0,
		"TCP port on which to serve a Prometheus-compatible metrics endpoint at `/metrics` (default: no metrics)")

	// --metrics-namespace (only settable via flag, no configuration file field)
	IroncladCmd.Flags().StringVar(&metricsNamespace, "metrics-namespace", "ironclad",
		"Namespace (prefix) for metrics exposed")

	// --health-port (only settable via flag, no configuration file field)
	IroncladCmd.Flags().Uint16Var(&healthPort, "health-port", 0,
		"TCP port on which to serve Kubernetes `/live` and `/ready` endpoints (default: no health listener)")

	// --log-format (also settable as logFormat in configuration file)
	IroncladCmd.Flags().String("log-format", "text", "Log format (text or json)")
	viper.BindPFlag("logFormat", IroncladCmd.Flag("log-format"))
	viper.SetDefault("logFormat", "text")

	// --log-level (also settable as logLevel in configuration file)
	IroncladCmd.Flags().String("log-level", "info", "Log level")
	viper.BindPFlag("logLevel", IroncladCmd.Flag("log-level"))
	viper.SetDefault("logLevel", "info")

	// --listen-port (also settable as listenPort in configuration file)
	IroncladCmd.Flags().Uint16("listen-port", 80, "TCP port where nginx should listen for HTTP requests")
	viper.BindPFlag("listenPort", IroncladCmd.Flag("listen-port"))
	viper.SetDefault("listenPort", 80)

	// --backend-port (also settable as backendPort in configuration file)
	IroncladCmd.Flags().Uint16("backend-port", 8080, "Backend TCP port to which nginx will proxy HTTP requests")
	viper.BindPFlag("backendPort", IroncladCmd.Flag("backend-port"))
	viper.SetDefault("backendPort", 8080)

	// --detection-only (also settable as detectionOnly in configuration file)
	IroncladCmd.Flags().Bool("detection-only", false, "Run in detection-only mode (don't block bad requests).")
	viper.BindPFlag("detectionOnly", IroncladCmd.Flag("detection-only"))
	viper.SetDefault("detectionOnly", false)

	// --trusted-proxy-ip-range (also settable as trustedProxyIPRanges in configuration file)
	IroncladCmd.Flags().StringSlice("trusted-proxy-ip-range", []string{},
		"IP ranges which are trusted to send a correct X-Forwarded-For header")
	viper.BindPFlag("trustedProxyIPRanges", IroncladCmd.Flag("trusted-proxy-ip-range"))

	if err := IroncladCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
