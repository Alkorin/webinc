package main

import (
	"os"

	log "github.com/sirupsen/logrus"
)

type FatalHook struct {
}

func NewFatalHook() *FatalHook {
	return &FatalHook{}
}

func (f *FatalHook) Fire(e *log.Entry) error {
	formatter := log.TextFormatter{FullTimestamp: true, ForceColors: true}
	msg, _ := formatter.Format(e)
	os.Stderr.Write(msg)
	return nil
}

func (f *FatalHook) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
	}
}
