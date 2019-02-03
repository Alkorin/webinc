package main

import (
	"os"

	"github.com/ovh/configstore"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	file, err := os.OpenFile("webinc.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
}

func main() {
	configstore.File("webinc.conf")
	config := configstore.Filter().Squash()

	token, err := config.MustGetItem("auth-token").Value()
	if err != nil {
		log.WithError(err).Fatal("Missing auth-token in webinc.conf")
	}

	logLevelString, err := config.MustGetItem("log-level").Value()
	if err == nil {
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
	device, err := NewDevice(token)
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

	log.Debug("Connecting to KMS...")
	kms, err := NewKMS(device, mercury)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Done")

	// Message Handler
	NewConversation(device, mercury, kms)

	log.Info("Ready")

	//Infinite wait
	select {}
}
