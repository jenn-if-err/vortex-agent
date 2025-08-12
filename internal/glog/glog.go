package glog

import (
	"github.com/flowerinthenight/vortex-agent/params"
	"github.com/golang/glog"
)

func LogInfof(format string, args ...interface{}) {
	force := false
	if len(args) > 0 {
		ok, f := args[0].(bool)
		if ok {
			force = f
		}
	}
	if params.RunfDisableLogs && !force {
		return
	}
	glog.Infof(format, args[1:]...)
}

func LogInfo(args ...interface{}) {
	force := false
	if len(args) > 0 {
		ok, f := args[0].(bool)
		if ok {
			force = f
		}
	}
	if params.RunfDisableLogs && !force {
		return
	}
	glog.Info(args...)
}
