package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

type SpaceTags []string

func (s SpaceTags) Contains(tag string) bool {
	for _, v := range s {
		if v == tag {
			return true
		}
	}
	return false
}

type Space struct {
	Id                           string
	EncryptionKey                *jose.JSONWebKey
	DefaultActivityEncryptionKey *jose.JSONWebKey
	KmsResourceObjectUrl         string
	DisplayName                  string
	Participants                 []string
	Tags                         SpaceTags
	Team                         *Team
	Activities                   []*Activity
	LastSeenActivityDate         time.Time

	conversation    *Conversation
	logger          *log.Entry
	activitiesMap   map[string]*Activity
	activitiesMutex sync.RWMutex
}

type RawSpace struct {
	Id                              string
	DisplayName                     string
	EncryptionKeyUrl                string
	DefaultActivityEncryptionKeyUrl string
	KmsResourceObjectUrl            string
	Tags                            SpaceTags

	Participants struct {
		Items []struct {
			DisplayName string
			EntryUUID   string
		}
	}

	Team struct {
		Id string
	}

	Activities struct {
		Items []Activity
	}

	LastSeenActivityDate time.Time
}

func (s *Space) IsOneOnOne() bool {
	return s.Tags.Contains("ONE_ON_ONE")
}

func (r *RawSpace) IsHidden() bool {
	return r.Tags.Contains("HIDDEN")
}

func (s *Space) Update(r RawSpace) {
	logger := s.conversation.logger.WithField("func", "Update").WithField("rawSpace", r)
	// Team ?
	if r.Team.Id != "" {
		logger = logger.WithField("teamId", r.Team.Id)
		team, err := s.conversation.GetTeam(r.Team.Id)
		if err != nil {
			logger.WithError(err).Error("Failed to get team infos")
		} else {
			s.Team = team
		}
	}

	// (Other) Participants
	newParticipants := []string{}
	for _, v := range r.Participants.Items {
		if v.EntryUUID == s.conversation.device.UserID {
			continue
		}
		newParticipants = append(newParticipants, v.DisplayName)
	}
	s.Participants = newParticipants

	// Activities
	for _, v := range r.Activities.Items {
		if v.Verb == "post" || v.Verb == "share" {
			s.AddActivity(v)
		}
	}

	// DisplayName
	if s.Tags.Contains("TEAM") {
		s.DisplayName = "General"
	} else if r.DisplayName != "" {
		if strings.Count(r.DisplayName, ".") == 4 {
			// DisplayName is encrypted
			displayName, err := s.Decrypt(r.DisplayName)
			if err == nil {
				s.DisplayName = string(displayName)
			} else {
				logger.WithError(err).Error("Failed to decrypt display name")
				// Failed to decrypt, keep value
				s.DisplayName = r.DisplayName
			}
		} else {
			// Doesn't looks like JWE, keep value
			s.DisplayName = r.DisplayName
		}
	} else {
		// No DisplayName, use participants
		s.DisplayName = strings.Join(s.Participants, ", ")
	}
}

func (s *Space) SendMessage(msg string) error {
	logger := s.logger.WithField("func", "SendMessage")

	encryptedMessage, err := s.EncryptActivity([]byte(msg))
	if err != nil {
		return errors.Wrap(err, "failed to encrypt message")
	}

	activity := struct {
		ClientTempId     string `json:"clientTempId"`
		EncryptionKeyUrl string `json:"encryptionKeyUrl"`
		ObjectType       string `json:"objectType"`
		Object           struct {
			DisplayName string `json:"displayName"`
			ObjectType  string `json:"objectType"`
		} `json:"object"`
		Target struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		} `json:"target"`
		Verb string `json:"verb"`
	}{
		ClientTempId:     uuid.Must(uuid.NewV4()).String(),
		EncryptionKeyUrl: s.DefaultActivityEncryptionKey.KeyID,
		ObjectType:       "activity",
		Verb:             "post",
	}
	activity.Object.DisplayName = encryptedMessage
	activity.Object.ObjectType = "comment"
	activity.Target.Id = s.Id
	activity.Target.ObjectType = "conversation"

	data, err := json.Marshal(activity)
	if err != nil {
		return errors.Wrap(err, "failed to marshal activity")
	}

	logger.Trace("Send message")
	s.conversation.activityQueue <- bytes.NewReader(data)
	return nil
}

func (s *Space) SendAcknowledge() error {
	logger := s.logger.WithField("func", "SendAcknowledge")

	activity := struct {
		ClientTempId string `json:"clientTempId"`
		ObjectType   string `json:"objectType"`
		Object       struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		} `json:"object"`
		Target struct {
			Id         string `json:"id"`
			ObjectType string `json:"objectType"`
		} `json:"target"`
		Verb string `json:"verb"`
	}{
		ClientTempId: uuid.Must(uuid.NewV4()).String(),
		ObjectType:   "activity",
		Verb:         "acknowledge",
	}
	activity.Object.Id = s.Activities[len(s.Activities)-1].Id
	activity.Object.ObjectType = "activity"
	activity.Target.Id = s.Id
	activity.Target.ObjectType = "conversation"

	data, err := json.Marshal(activity)
	if err != nil {
		return errors.Wrap(err, "failed to marshal activity")
	}

	logger.Trace("Send message")
	s.conversation.activityQueue <- bytes.NewReader(data)
	return nil
}

func (s *Space) Decrypt(encryptedString string) ([]byte, error) {
	encryptedObject, err := jose.ParseEncrypted(encryptedString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse encrypted message")
	}

	key := s.EncryptionKey
	if key == nil {
		key = s.DefaultActivityEncryptionKey
	}

	decrypted, err := encryptedObject.Decrypt(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt message")
	}
	return decrypted, nil
}

func (s *Space) EncryptActivity(data []byte) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: s.DefaultActivityEncryptionKey}, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create jose encrypter")
	}

	object, err := encrypter.Encrypt(data)
	if err != nil {
		return "", errors.Wrap(err, "failed to encrypt kms request")
	}

	return object.CompactSerialize()
}

func (s *Space) AddActivity(a Activity) *Activity {
	logger := s.logger.WithField("func", "AddActivity").WithField("activity", a)

	s.activitiesMutex.Lock()
	defer s.activitiesMutex.Unlock()

	// Already seen activity, drop
	if a, ok := s.activitiesMap[a.Id]; ok {
		return a
	}

	// Decrypt name if defined
	if a.Object.DisplayName != "" {
		displayName, err := s.Decrypt(a.Object.DisplayName)
		if err != nil {
			logger.WithError(err).Error("Failed to decrypt display name")
		} else {
			a.Object.DisplayName = string(displayName)
		}
	}

	// Insert at the end and see if we need to move the data
	s.Activities = append(s.Activities, &a)
	length := len(s.Activities)
	if length > 1 && s.Activities[length-2].Published.After(a.Published) {
		// Our inserted element is older than the last one, walk until we find its place
		i := length - 2
		for ; i >= 0; i-- {
			if s.Activities[i].Published.Before(a.Published) {
				break
			}
		}
		copy(s.Activities[i+2:], s.Activities[i+1:length-1])
		s.Activities[i+1] = &a
	}

	// Store in seen map
	s.activitiesMap[a.Id] = &a

	return &a
}

func (s *Space) HasUnseenActivities() bool {
	s.activitiesMutex.RLock()
	defer s.activitiesMutex.RUnlock()

	if len(s.Activities) > 0 && s.Activities[len(s.Activities)-1].Published.After(s.LastSeenActivityDate) {
		return true
	}

	return false
}
