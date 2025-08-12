package glog

import (
	"github.com/flowerinthenight/vortex-agent/params"
	"github.com/golang/glog"
)

func LogInfof(format string, args ...interface{}) {
	force := false
	if len(args) > 0 {
		f, ok := args[0].(bool)
		if ok {
			force = f
			args = args[1:]
		}
	}
	if params.RunfDisableLogs && !force {
		return
	}
	glog.Infof(format, args...)
}

func LogInfo(args ...interface{}) {
	force := false
	if len(args) > 0 {
		f, ok := args[0].(bool)
		if ok {
			force = f
			args = args[1:]
		}
	}
	if params.RunfDisableLogs && !force {
		return
	}
	glog.Info(args...)
}
