package main

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Conversation struct {
	device  *Device
	mercury *Mercury
	kms     *KMS

	spaces      map[string]*Space
	spacesMutex sync.RWMutex

	teams      map[string]*Team
	teamsMutex sync.RWMutex

	logger *log.Entry
}

type Team struct {
	Id          string
	DisplayName string
}

func NewConversation(device *Device, mercury *Mercury, kms *KMS) *Conversation {
	c := &Conversation{
		device:  device,
		mercury: mercury,
		kms:     kms,
		spaces:  make(map[string]*Space),
		teams:   make(map[string]*Team),
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
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Target.Id)
		logger.Trace("Post in space")

		space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
		if err != nil {
			logger.WithError(err).Error("Failed to get space")
			return
		}

		displayName, err := space.Decrypt(mercuryConversationActivity.Data.Activity.Object.DisplayName)
		if err != nil {
			logger.WithError(err).Error("Failed to decrypt display name")
			return
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
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Target.Id)
		logger.Trace("Update space")

		space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
		if err != nil {
			logger.WithError(err).Error("Failed to get space")
			return
		}

		displayName, err := space.Decrypt(mercuryConversationActivity.Data.Activity.Object.DisplayName)
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

	for _, space := range r.Items {
		logger := logger.WithField("rawSpace", space)
		if space.Tags.Contains("HIDDEN") {
			continue
		}

		_, err := c.AddSpace(space)
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
	logger.Trace("Adding space")

	// Fetch conversation key
	logger = logger.WithField("kid", r.EncryptionKeyUrl)
	key, err := c.kms.GetKey(r.EncryptionKeyUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fech decryption key")
	}

	space := &Space{
		Id:            r.Id,
		EncryptionKey: key,
		Tags:          r.Tags,

		conversation: c,
		logger:       c.logger.WithField("spaceId", r.Id),
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

func (c *Conversation) GetTeam(uuid string) (*Team, error) {
	logger := c.logger.WithField("func", "GetTeam").WithField("uuid", uuid)
	c.teamsMutex.RLock()
	if team, ok := c.teams[uuid]; ok {
		c.teamsMutex.RUnlock()
		return team, nil
	}
	c.teamsMutex.RUnlock()

	// Fetch Team
	logger.Trace("Request Team")
	response, err := c.device.RequestService("GET", "conversationServiceUrl", "/teams/"+uuid, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch team")
	}
	defer response.Body.Close()

	var rawTeam struct {
		Id               string
		EncryptionKeyUrl string
		DisplayName      string
	}
	err = json.NewDecoder(response.Body).Decode(&rawTeam)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch unmarshal team")
	}
	logger = logger.WithField("rawTeam", rawTeam)
	logger.Trace("Got team")

	displayName, err := c.kms.Decrypt(rawTeam.DisplayName, rawTeam.EncryptionKeyUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt displayName")
	}

	team := &Team{
		Id:          rawTeam.Id,
		DisplayName: string(displayName),
	}

	// Store
	c.teamsMutex.Lock()
	c.teams[uuid] = team
	c.teamsMutex.Unlock()

	return team, nil
}
