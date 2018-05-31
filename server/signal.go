// Copyright 2017 Apcera Inc. All rights reserved.
// +build !windows

package server

import (
	"os"
	"os/signal"
	"syscall"
)

// Signal Handling
func (s *StanServer) handleSignals() {
	c := make(chan os.Signal, 1)

	//2017-12-26
	//signal.Notify(c, syscall.SIGINT, syscall.SIGUSR1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGHUP,syscall.SIGUSR1)
	go func() {
		for sig := range c {
			// Notify will relay only the signals that we have
			// registered, so we don't need a "default" in the
			// switch statement.
			switch sig {
			case syscall.SIGKILL, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT:
				//2017-12-26
				s.log.Noticef("get signal:%v, will UnRegister()", sig)
				s.opts.ConsulUtil.UnRegister()

				s.Shutdown()
				os.Exit(0)
			case syscall.SIGUSR1:
				// File log re-open for rotating file logs.
				s.natsServer.ReOpenLogFile()
			}
		}
	}()
}
