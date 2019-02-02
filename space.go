package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

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
	Id            string
	EncryptionKey jose.JSONWebKey
	DisplayName   string
	Participants  []string
	Tags          SpaceTags
	Team          *Team

	conversation *Conversation
	logger       *log.Entry
}

type RawSpace struct {
	Id               string
	DisplayName      string
	EncryptionKeyUrl string
	Tags             SpaceTags

	Participants struct {
		Items []struct {
			DisplayName string
			EntryUUID   string
		}
	}

	Team struct {
		Id string
	}
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
	return
}

func (s *Space) SendMessage(msg string) error {
	logger := s.logger.WithField("func", "SendMessage")

	encryptedMessage, err := s.Encrypt([]byte(msg))
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
		EncryptionKeyUrl: s.EncryptionKey.KeyID,
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
	response, err := s.conversation.device.RequestService("POST", "conversationServiceUrl", "/activities", bytes.NewReader(data))
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	if response.StatusCode != http.StatusOK {
		responseError, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read error response")
		}
		return errors.Errorf("failed to send message: %s", responseError)
	}

	return nil
}

func (s *Space) Decrypt(encryptedString string) ([]byte, error) {
	encryptedObject, err := jose.ParseEncrypted(encryptedString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse encrypted message")
	}

	decrypted, err := encryptedObject.Decrypt(s.EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt message")
	}
	return decrypted, nil
}

func (s *Space) Encrypt(data []byte) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: s.EncryptionKey}, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create jose encrypter")
	}

	object, err := encrypter.Encrypt(data)
	if err != nil {
		return "", errors.Wrap(err, "failed to encrypt kms request")
	}

	return object.CompactSerialize()
}
