package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/gofrs/uuid"
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

	newSpaceEventHandlers    []func(*Space)
	removeSpaceEventHandlers []func(*Space)
	newActivityEventHandlers []func(*Space, *Activity)

	activityQueue chan io.Reader

	logger *log.Entry
}

type Team struct {
	Id          string
	DisplayName string
}

func NewConversation(device *Device, mercury *Mercury, kms *KMS) *Conversation {
	c := &Conversation{
		device:        device,
		mercury:       mercury,
		kms:           kms,
		spaces:        make(map[string]*Space),
		teams:         make(map[string]*Team),
		logger:        log.WithField("type", "Conversation"),
		activityQueue: make(chan io.Reader, 64),
	}

	mercury.RegisterHandler("conversation.activity", c.ParseActivity)

	// Fetch current spaces
	go c.FetchAllSpaces()
	go c.HandleActivityQueue()

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
	case "post", "share":
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Target.Id).WithField("verb", mercuryConversationActivity.Data.Activity.Verb)
		logger.Trace("Post in space")

		space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
		if err != nil {
			logger.WithError(err).Error("Failed to get space")
			return
		}

		a := space.AddActivity(mercuryConversationActivity.Data.Activity)

		for _, f := range c.newActivityEventHandlers {
			f(space, a)
		}
		logger.Trace("New space")
	case "add":
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Target.Id).WithField("verb", mercuryConversationActivity.Data.Activity.Verb)
		logger.Trace("New space")

		if mercuryConversationActivity.Data.Activity.Object.EntryUUID == c.device.UserID {
			space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
			if err != nil {
				logger.WithError(err).Error("Failed to get space")
				return
			}

			for _, f := range c.newActivityEventHandlers {
				f(space, &mercuryConversationActivity.Data.Activity)
			}
		}
	case "create":
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Object.Id).WithField("verb", mercuryConversationActivity.Data.Activity.Verb)
		logger.Trace("New space")

		if mercuryConversationActivity.Data.Activity.Actor.EntryUUID == c.device.UserID {
			space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Object.Id)
			if err != nil {
				logger.WithError(err).Error("Failed to get space")
				return
			}

			for _, f := range c.newActivityEventHandlers {
				f(space, &mercuryConversationActivity.Data.Activity)
			}
		}
	case "hide":
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Object.Id).WithField("verb", mercuryConversationActivity.Data.Activity.Verb)
		logger.Trace("Leave space")

		if mercuryConversationActivity.Data.Activity.Actor.EntryUUID == c.device.UserID {
			space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Object.Id)
			if err != nil {
				logger.WithError(err).Error("Failed to get space")
				return
			}

			for _, f := range c.removeSpaceEventHandlers {
				f(space)
			}

			c.RemoveSpace(space)
		}
	case "leave":
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Target.Id).WithField("verb", mercuryConversationActivity.Data.Activity.Verb)
		logger.Trace("Leave space")

		if mercuryConversationActivity.Data.Activity.Object.EntryUUID == c.device.UserID {
			space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
			if err != nil {
				logger.WithError(err).Error("Failed to get space")
				return
			}

			for _, f := range c.removeSpaceEventHandlers {
				f(space)
			}

			c.RemoveSpace(space)
		}
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
		logger = logger.WithField("space", mercuryConversationActivity.Data.Activity.Target.Id)
		if mercuryConversationActivity.Data.Activity.Actor.EntryUUID == c.device.UserID {
			logger.Trace("Space marked as read")

			space, err := c.GetSpace(mercuryConversationActivity.Data.Activity.Target.Id)
			if err != nil {
				logger.WithError(err).Error("Failed to get space")
				return
			}

			space.LastSeenActivityDate = mercuryConversationActivity.Data.Activity.Published
			for _, f := range c.newActivityEventHandlers {
				f(space, &mercuryConversationActivity.Data.Activity)
			}
		}
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

	space := &Space{
		Id:                   r.Id,
		Tags:                 r.Tags,
		LastSeenActivityDate: r.LastSeenActivityDate,
		KmsResourceObjectUrl: r.KmsResourceObjectUrl,

		conversation:  c,
		activitiesMap: make(map[string]*Activity),
		logger:        c.logger.WithField("type", "Space").WithField("spaceId", r.Id),
	}

	// Prefetch keys
	if r.EncryptionKeyUrl != "" {
		key, err := c.kms.GetKey(r.EncryptionKeyUrl)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fech decryption key")
		}
		space.EncryptionKey = key
	}
	if r.DefaultActivityEncryptionKeyUrl != "" {
		key, err := c.kms.GetKey(r.DefaultActivityEncryptionKeyUrl)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fech decryption key")
		}
		space.DefaultActivityEncryptionKey = key
	}

	// Store & Update space
	c.spacesMutex.Lock()
	if s, ok := c.spaces[space.Id]; !ok {
		c.spaces[space.Id] = space
		c.spacesMutex.Unlock()
		space.Update(r)
		// Events
		for _, f := range c.newSpaceEventHandlers {
			f(space)
		}
		return space, nil
	} else {
		// Space already exists, return current
		c.spacesMutex.Unlock()
		return s, nil
	}
}

func (c *Conversation) RemoveSpace(space *Space) {
	c.spacesMutex.Lock()
	delete(c.spaces, space.Id)
	c.spacesMutex.Unlock()
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

func (c *Conversation) AddNewSpaceEventHandler(f func(*Space)) {
	c.newSpaceEventHandlers = append(c.newSpaceEventHandlers, f)
}

func (c *Conversation) AddRemoveSpaceEventHandler(f func(*Space)) {
	c.removeSpaceEventHandlers = append(c.removeSpaceEventHandlers, f)
}

func (c *Conversation) AddNewActivityEventHandler(f func(*Space, *Activity)) {
	c.newActivityEventHandlers = append(c.newActivityEventHandlers, f)
}

func (c *Conversation) HandleActivityQueue() {
	for data := range c.activityQueue {
		response, err := c.device.RequestService("POST", "conversationServiceUrl", "/activities", data)
		if err != nil {
			log.WithError(err).Error("Failed to create request")
			continue
		}

		if response.StatusCode != http.StatusOK {
			responseError, err := ioutil.ReadAll(response.Body)
			if err != nil {
				c.logger.WithError(err).Error("Failed to read error response")
			} else {
				c.logger.WithError(errors.New(string(responseError))).Error("Failed to send message")
			}
		}

		response.Body.Close()
	}
}

func (c *Conversation) CreateSpace(name string) {
	logger := c.logger.WithField("func", "CreateSpace").WithField("spaceName", name)

	// Create a new encryption key
	key, err := c.kms.CreateKey()
	if err != nil {
		logger.WithError(err).Error("Failed to create space encryption key")
		return
	}

	encryptedName, err := EncryptWithKey([]byte(name), key)
	if err != nil {
		logger.WithError(err).Error("Failed to encrypt space name")
		return
	}

	// Create a KMS request
	kmsMessage, err := c.kms.NewResourceCreateMessage(key)
	if err != nil {
		logger.WithError(err).Error("Failed create new ressource KMS message")
		return
	}

	// Forge request
	type newSpaceActivityObject struct {
		Id         string `json:"id"`
		ObjectType string `json:"objectType"`
	}

	type newSpaceActivity struct {
		Verb       string                  `json:"verb"`
		ObjectType string                  `json:"objectType"`
		Actor      newSpaceActivityObject  `json:"actor"`
		Object     *newSpaceActivityObject `json:"object,omitempty"`
	}

	newSpace := struct {
		Activities struct {
			Items []newSpaceActivity `json:"items"`
		} `json:"activities"`
		DefaultActivityEncryptionKeyUrl string `json:"defaultActivityEncryptionKeyUrl"`
		DisplayName                     string `json:"displayName"`
		EncryptionKeyUrl                string `json:"encryptionKeyUrl"`
		ObjectType                      string `json:"objectType"`
		KmsMessage                      string `json:"kmsMessage"`
	}{
		DefaultActivityEncryptionKeyUrl: key.KeyID,
		DisplayName:                     encryptedName,
		EncryptionKeyUrl:                key.KeyID,
		ObjectType:                      "conversation",
		KmsMessage:                      kmsMessage,
	}

	newSpace.Activities.Items = []newSpaceActivity{
		{
			Verb:       "create",
			ObjectType: "activity",
			Actor: newSpaceActivityObject{
				ObjectType: "person",
				Id:         c.device.UserID,
			},
		},
		{
			Verb:       "add",
			ObjectType: "activity",
			Actor: newSpaceActivityObject{
				ObjectType: "person",
				Id:         c.device.UserID,
			},
			Object: &newSpaceActivityObject{
				ObjectType: "person",
				Id:         c.device.UserID,
			},
		},
	}

	data, err := json.Marshal(newSpace)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal new space request")
		return
	}

	response, err := c.device.RequestService("POST", "conversationServiceUrl", "/conversations", bytes.NewReader(data))
	if err != nil {
		logger.WithError(err).Error("Failed to request space creation")
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		responseError, err := ioutil.ReadAll(response.Body)
		if err != nil {
			logger.WithError(err).Error("Failed to read error response")
			return
		}

		logger.Errorf("Failed to request ace creation: %s", responseError)
		return
	}
}

func (c *Conversation) LeaveSpace(space *Space) {
	logger := c.logger.WithField("func", "LeaveSpace").WithField("spaceId", space.Id)

	if space.IsOneOnOne() {
		c.leaveOneOnOne(space)
		return
	}

	// Create a KMS request
	kmsMessage, err := c.kms.NewDeleteAuthorizationMessage(space.KmsResourceObjectUrl, c.device.UserID)
	if err != nil {
		logger.WithError(err).Error("Failed to create new Delete Authorization KMS message")
		return
	}

	activity := struct {
		ClientTempId string `json:"clientTempId"`
		ObjectType   string `json:"objectType"`
		Object       struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		} `json:"object"`
		Actor struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		}
		Target struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		} `json:"target"`
		Verb       string `json:"verb"`
		KmsMessage string `json:"kmsMessage"`
	}{
		ClientTempId: uuid.Must(uuid.NewV4()).String(),
		ObjectType:   "activity",
		Verb:         "leave",
		KmsMessage:   kmsMessage,
	}
	activity.Actor.Id = space.Id
	activity.Actor.ObjectType = "conversation"
	activity.Object.Id = c.device.UserID
	activity.Object.ObjectType = "person"
	activity.Target.Id = space.Id
	activity.Target.ObjectType = "conversation"

	data, err := json.Marshal(activity)
	if err != nil {
		c.logger.WithError(err).Error("Failed to marshal activity")
		return
	}

	logger.Trace("Send leave activity")
	c.activityQueue <- bytes.NewReader(data)
	return
}

func (c *Conversation) leaveOneOnOne(space *Space) {
	logger := c.logger.WithField("func", "LeaveOneOnOneSpace").WithField("spaceId", space.Id)

	if !space.IsOneOnOne() {
		return
	}

	activity := struct {
		ClientTempId string `json:"clientTempId"`
		ObjectType   string `json:"objectType"`
		Object       struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		} `json:"object"`
		Actor struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		}
		Verb string `json:"verb"`
	}{
		ClientTempId: uuid.Must(uuid.NewV4()).String(),
		ObjectType:   "activity",
		Verb:         "hide",
	}
	activity.Actor.Id = c.device.UserID
	activity.Actor.ObjectType = "person"
	activity.Object.Id = space.Id
	activity.Object.ObjectType = "conversation"

	data, err := json.Marshal(activity)
	if err != nil {
		c.logger.WithError(err).Error("Failed to marshal activity")
		return
	}

	logger.Trace("Send leave activity")
	c.activityQueue <- bytes.NewReader(data)
	return
}
