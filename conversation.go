package main

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

type Conversation struct {
	mercury *Mercury
	kms     *KMS

	logger *log.Entry
}

func NewConversation(mercury *Mercury, kms *KMS) *Conversation {
	c := &Conversation{
		mercury: mercury,
		kms:     kms,
		logger:  log.WithField("type", "Conversation"),
	}

	mercury.RegisterHandler("conversation.activity", c.ParseActivity)
	return c
}

func (c *Conversation) ParseActivity(msg []byte) {
	logger := c.logger.WithField("func", "ParseActivity").WithField("message", string(msg))

	var mercuryConversationActivity MercuryConversationActivity
	err := json.Unmarshal(msg, &mercuryConversationActivity)
	if err != nil {
		log.WithError(err).Error("Failed to unmarshal msg")
		return
	}

	logger = logger.WithField("activity", mercuryConversationActivity)
	switch mercuryConversationActivity.Data.Activity.Verb {
	case "post":
		encryptedDisplayName, err := jose.ParseEncrypted(mercuryConversationActivity.Data.Activity.Object.DisplayName)
		if err != nil {
			logger.WithError(err).Error("Failed to parse object displayname")
			return
		}
		kid := mercuryConversationActivity.Data.Activity.EncryptionKeyUrl
		logger = logger.WithField("kid", kid)

		logger.Trace("Request key")
		key, err := c.kms.GetKey(kid)
		if err != nil {
			logger.WithError(err).Error("Failed to fech decryption key")
		}

		logger.Trace("Got key")
		displayName, err := encryptedDisplayName.Decrypt(key)
		if err != nil {
			logger.WithError(err).Error("Failed to decrypt display name")
		}
		fmt.Printf("%+v> %s - %s\n", mercuryConversationActivity.Data.Activity.Target.Id, mercuryConversationActivity.Data.Activity.Actor.Id, displayName)
	default:
		logger.Error("Unhandled verb")
	}
}
