package main

import (
	"encoding/json"
	"fmt"
	"strings"
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
	Id            string
	EncryptionKey jose.JSONWebKey
	DisplayName   string
	Participants  []string

	conversation *Conversation
}

type RawSpace struct {
	Id               string
	DisplayName      string
	EncryptionKeyUrl string

	Participants struct {
		Items []struct {
			DisplayName string
			EntryUUID   string
		}
	}
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

	// Fetch current spaces
	go c.FetchAllSpaces()

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
		logger.Trace("Post in space")
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
	case "leave":
		logger.Trace("Leave space")
	case "hide":
		logger.Trace("Leave space")
	case "update":
		logger.Trace("Update space")
		encryptedDisplayName, err := jose.ParseEncrypted(mercuryConversationActivity.Data.Activity.Object.DisplayName)
		if err != nil {
			logger.WithError(err).Error("Failed to parse object displayname")
			return
		}
		logger.Trace("Get space")
		space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
		if err != nil {
			logger.WithError(err).Error("Failed to fetch space")
		}

		displayName, err := encryptedDisplayName.Decrypt(space.EncryptionKey)
		if err != nil {
			logger.WithError(err).Error("Failed to decrypt display name")
			return
		}
		space.DisplayName = string(displayName)
	case "acknowledge":
		logger.Trace("Space marked as read")
	default:
		logger.Error("Unhandled verb")
	}
}

func (c *Conversation) FetchAllSpaces() {
	logger := c.logger.WithField("func", "FetchAllSpaces")

	// Fetch spaces
	logger.Trace("Request conversations")
	response, err := c.device.RequestService("GET", "conversationServiceUrl", "/conversations", nil)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch conversations")
		return
	}
	defer response.Body.Close()

	var r struct {
		Items []RawSpace
	}
	err = json.NewDecoder(response.Body).Decode(&r)
	if err != nil {
		logger.WithError(err).Error("Failed to unmarshal conversations")
		return
	}

	for _, i := range r.Items {
		logger := logger.WithField("rawSpace", i)
		_, err := c.AddSpace(i)
		if err != nil {
			logger.WithError(err).Error("Failed to add space")
			continue
		}
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
	logger.Trace("Request conversation")
	response, err := c.device.RequestService("GET", "conversationServiceUrl", "/conversations/"+uuid, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch conversation")
	}
	defer response.Body.Close()

	var r RawSpace
	err = json.NewDecoder(response.Body).Decode(&r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch conversation")
	}

	return c.AddSpace(r)
}

func (c *Conversation) AddSpace(r RawSpace) (*Space, error) {
	logger := c.logger.WithField("func", "AddSpace").WithField("rawSpace", r)

	// Fetch conversation key
	logger = logger.WithField("kid", r.EncryptionKeyUrl)
	key, err := c.kms.GetKey(r.EncryptionKeyUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fech decryption key")
	}

	space := &Space{
		Id:            r.Id,
		EncryptionKey: key,

		conversation: c,
	}

	// Store & Update space
	c.spacesMutex.Lock()
	if s, ok := c.spaces[space.Id]; !ok {
		c.spaces[space.Id] = space
		c.spacesMutex.Unlock()
		space.Update(r)
		return space, nil
	} else {
		// Space already exists, return current
		c.spacesMutex.Unlock()
		return s, nil
	}
}

func (s *Space) Update(r RawSpace) {
	logger := s.conversation.logger.WithField("func", "Update").WithField("rawSpace", r)
	newParticipants := []string{}
	// (Other) Participants
	for _, v := range r.Participants.Items {
		if v.EntryUUID == s.conversation.device.UserID {
			continue
		}
		newParticipants = append(newParticipants, v.DisplayName)
	}
	s.Participants = newParticipants

	// DisplayName
	if r.DisplayName != "" {
		if strings.Count(r.DisplayName, ".") == 4 {
			// DisplayName is encrypted
			encryptedDisplayName, err := jose.ParseEncrypted(r.DisplayName)
			if err == nil {
				displayName, err := encryptedDisplayName.Decrypt(s.EncryptionKey)
				if err == nil {
					s.DisplayName = string(displayName)
				} else {
					logger.WithError(err).Error("Failed to decrypt display name")
				}
			} else {
				logger.WithError(err).Error("Failed to decrypt display name")
			}
		}
		// Failed to decrypt, keep value
		if s.DisplayName == "" {
			s.DisplayName = r.DisplayName
		}
	} else {
		// No DisplayName, use participants
		s.DisplayName = strings.Join(s.Participants, ", ")
	}
	return
}
