package main

import (
	"encoding/json"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Mercury struct {
	Device   *Device
	Handlers map[string]func([]byte)

	logger *log.Entry
}

func NewMercury(device *Device) (*Mercury, error) {
	mercury := &Mercury{
		Device:   device,
		Handlers: make(map[string]func([]byte)),
		logger:   log.WithField("type", "Mercury"),
	}

	logger := mercury.logger.WithField("websocketUrl", device.WebSocketUrl)

	conn, resp, err := websocket.DefaultDialer.Dial(device.WebSocketUrl, nil)
	if err != nil {
		logger.WithField("websocketResponse", resp).Error("Failed to dial WS")
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, ErrInvalidDevice
		}
		return nil, errors.Wrap(err, "failed to connect to mercury service")
	}

	var authRequest MercuryAuthRequest
	authRequest.Id = uuid.Must(uuid.NewV4()).String()
	authRequest.Type = "authorization"
	authRequest.Data.Token = "Bearer " + device.Token

	authRequestData, err := json.Marshal(authRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal mercury auth request")
	}

	logger.Trace("Sending Auth Request...")
	err = conn.WriteMessage(websocket.TextMessage, authRequestData)
	if err != nil {
		panic(err)
	}

	// Start Mercury Goroutine
	go func() {
		for {
			logger.Trace("Waiting msgs...")
			_, msg, err := conn.ReadMessage()
			if err != nil {
				panic(err)
			}
			logger := logger.WithField("message", string(msg))
			logger.Trace("Message received")

			var mercuryMessage MercuryMessage
			err = json.Unmarshal(msg, &mercuryMessage)
			if err != nil {
				logger.WithError(err).Errorf("Failed to parse mercury message")
				continue
			}

			// Send ACK
			ack, err := json.Marshal(MercuryAck{MessageId: mercuryMessage.Id, Type: "ack"})
			if err != nil {
				logger.WithError(err).Errorf("Failed to create mercury ack")
				continue
			}
			err = conn.WriteMessage(websocket.TextMessage, ack)
			if err != nil {
				panic(err)
			}

			handler, ok := mercury.Handlers[mercuryMessage.Data.EventType]
			if ok {
				go handler(msg)
			} else {
				logger.WithField("eventType", mercuryMessage.Data.EventType).Trace("Unhandled EventType")
			}
		}
	}()

	return mercury, nil
}

func (m *Mercury) RegisterHandler(eventType string, f func([]byte)) {
	m.Handlers[eventType] = f
}
