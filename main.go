package main

import (
	"github.com/ovh/configstore"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	configstore.File("webinc.conf")
	config := configstore.Filter().Squash()

	token, err := config.MustGetItem("auth-token").Value()
	if err != nil {
		log.WithError(err).Fatal("Missing auth-token in webinc.conf")
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
	NewConversation(mercury, kms)

	//Infinite wait
	select {}
}
