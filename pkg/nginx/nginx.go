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

package nginx

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"syscall"

	"github.com/sirupsen/logrus"
)

// Server represents a running nginx instance
type Server struct {
	cmd              *exec.Cmd
	stderr           io.Reader
	log              *logrus.Entry
	lastLoadedConfig Config
}

// Start an nginx process tree
func Start(config Config) (*Server, error) {
	// find nginx on PATH
	bin, err := exec.LookPath("nginx")
	if err != nil {
		return nil, err
	}

	// render the configuration into an nginx.conf file
	if err := config.write(); err != nil {
		return nil, err
	}

	// start nginx
	cmd := exec.Command(bin)

	// redirect nginx stdout to /dev/null
	cmd.Stdout, err = os.Open("/dev/null")
	if err != nil {
		return nil, err
	}

	// redirect stderr to a pipe so we can tail (and annotate) any error output
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	log := logrus.WithFields(logrus.Fields{
		"bin": bin,
		"pid": cmd.Process.Pid,
	})
	log.Info("started nginx")

	// return a handle that the caller can use to Reload() and WaitForExit()
	s := &Server{
		cmd:              cmd,
		stderr:           stderr,
		log:              log,
		lastLoadedConfig: config,
	}

	return s, nil
}

// Reload the running nginx instance with a fresh configuration
func (s *Server) Reload(config Config) {
	// bail out early if nothing has changed since the last reload
	if reflect.DeepEqual(s.lastLoadedConfig, config) {
		return
	}

	// re-render the configuration into an nginx.conf file
	if err := config.write(); err != nil {
		s.log.WithError(err).Error("could not write updated config")
		return
	}

	// signal nginx to reload
	s.log.Info("reloading nginx")
	if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		s.log.WithError(err).Error("could not send SIGHUP signal")
		return
	}

	// remember that we just loaded this config
	s.lastLoadedConfig = config
}

var nginxLogHeader = regexp.MustCompile(`[0-9/]+ [0-9:]+ \[[a-z]+\] (.+)`)

// WaitForExit waits for the running nginx to exit (tailing stderr to the log as it waits)
func (s *Server) WaitForExit() error {
	scanner := bufio.NewScanner(s.stderr)
	for scanner.Scan() {
		msg := scanner.Text()

		// strip off the nginx timestamp and error header, since we already know that
		matchIdx := nginxLogHeader.FindStringSubmatchIndex(msg)
		if len(matchIdx) == 4 {
			msg = msg[matchIdx[2]:matchIdx[3]]
		}

		s.log.WithField("type", "nginx").Error(msg)

	}
	if err := scanner.Err(); err != nil {
		s.log.WithError(err).Error("problem reading nginx output stream")
	}
	return s.cmd.Wait()
}
