package main

import (
	"os"
	"runtime/debug"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
}

func main() {
	// Catch panics and try to log them into error file
	defer func() {
		if err := recover(); err != nil {
			log.WithField("error", err).WithField("stack", string(debug.Stack())).Panic("Code paniced :(")
		}
	}()

	config, err := NewConfig()
	if err != nil {
		log.WithError(err).Fatal("Failed to read config")
	}

	log.Infof("Starting webinc version %q", buildVersion)
	file, err := os.OpenFile(config.GetString("log-file"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
	log.AddHook(NewFatalHook())

	logLevelString := config.GetString("log-level")
	if logLevelString != "" {
		logLevel, err := log.ParseLevel(logLevelString)
		if err != nil {
			log.WithError(err).Fatal("Invalid log-level")
		}
		log.SetLevel(logLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// Register Device
	log.Debug("Registering device...")
	device, err := NewDevice(config)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Done")

	// Start Mercury Service
	log.Debug("Connecting to Mercury...")
	mercury, err := NewMercury(device)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Done")

	// Start KMS Service
	log.Debug("Connecting to KMS...")
	kms, err := NewKMS(device, mercury)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Done")

	// Message Handler
	c := NewConversation(device, mercury, kms)

	// Start GUI
	g, err := NewGoCUI(c)
	if err != nil {
		log.Fatal(err)
	}

	g.Start()
}
