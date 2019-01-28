package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

type Conversation struct {
	device  *Device
	mercury *Mercury
	kms     *KMS

	spaces      map[string]*Space
	spacesMutex sync.RWMutex

	logger *log.Entry
}

type Space struct {
	DisplayName string
}

func NewConversation(device *Device, mercury *Mercury, kms *KMS) *Conversation {
	c := &Conversation{
		device:  device,
		mercury: mercury,
		kms:     kms,
		spaces:  make(map[string]*Space),
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
		logger.WithError(err).Error("Failed to unmarshal msg")
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
		logger = logger.WithField("kid", kid).WithField("space", mercuryConversationActivity.Data.Activity.Target.Id)

		logger.Trace("Request key")
		key, err := c.kms.GetKey(kid)
		if err != nil {
			logger.WithError(err).Error("Failed to fech decryption key")
			return
		}

		logger.Trace("Got key")
		displayName, err := encryptedDisplayName.Decrypt(key)
		if err != nil {
			logger.WithError(err).Error("Failed to decrypt display name")
			return
		}

		logger.Trace("Get space")
		space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
		if err != nil {
			logger.WithError(err).Error("Failed to fetch space")
		}
		fmt.Printf("%s> %s - %s\n", space.DisplayName, mercuryConversationActivity.Data.Activity.Actor.Id, displayName)
	case "add":
		logger.Trace("New space")
	case "create":
		logger.Trace("New space")
	case "hide":
		logger.Trace("Leave space")
	case "acknowledge":
		logger.Trace("Space marked as read")
	default:
		logger.Error("Unhandled verb")
	}
}

func (c *Conversation) GetSpace(uuid string) (*Space, error) {
	logger := c.logger.WithField("func", "GetSpace").WithField("uuid", uuid)
	c.spacesMutex.RLock()
	if space, ok := c.spaces[uuid]; ok {
		c.spacesMutex.RUnlock()
		return space, nil
	}
	c.spacesMutex.RUnlock()

	// Fetch conversation
	request, err := http.NewRequest("GET", c.device.Services["conversationServiceUrl"]+"/conversations/"+uuid, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create conversation request")
	}
	request.Header.Set("Authorization", "Bearer "+c.device.Token)

	logger.Trace("Request conversation")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch conversation")
	}
	defer response.Body.Close()

	var conversationInfos struct {
		DisplayName      string
		EncryptionKeyUrl string
	}
	err = json.NewDecoder(response.Body).Decode(&conversationInfos)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal conversation Infos")
	}

	// Fetch conversation key
	logger = logger.WithField("kid", conversationInfos.EncryptionKeyUrl)

	logger.Trace("Request key")
	key, err := c.kms.GetKey(conversationInfos.EncryptionKeyUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fech decryption key")
	}

	// Decrypt DisplayName
	encryptedDisplayName, err := jose.ParseEncrypted(conversationInfos.DisplayName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse object displayname")
	}
	displayName, err := encryptedDisplayName.Decrypt(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt display name")
	}

	space := Space{
		DisplayName: string(displayName),
	}

	c.spacesMutex.Lock()
	c.spaces[uuid] = &space
	c.spacesMutex.Unlock()

	return &space, nil
}
