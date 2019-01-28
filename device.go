package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	"io/ioutil"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const DEVICE_API_URL = "https://wdm-a.wbx2.com/wdm/api/v1/devices"

type Device struct {
	Token        string
	WebSocketUrl string
	Url          string
	UserID       string
	Services     map[string]string

	logger *log.Entry
}

func NewDevice(token string) (*Device, error) {
	logger := log.WithField("type", "Device")
	deviceRegisterRequest, err := json.Marshal(struct {
		DeviceName     string `json:"deviceName"`
		DeviceType     string `json:"deviceType"`
		LocalizedModel string `json:"localizedModel"`
		Model          string `json:"model"`
		Name           string `json:"name"`
		SystemName     string `json:"systemName"`
		SystemVersion  string `json:"systemVersion"`
	}{
		"webinc",
		"DESKTOP",
		"webinc",
		"webinc",
		"webinc",
		"webinc",
		buildVersion,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal deviceRegisterRequest")
	}

	request, err := http.NewRequest("POST", DEVICE_API_URL, bytes.NewBuffer(deviceRegisterRequest))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create http request")
	}

	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")

	logger.Trace("Create device")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create device")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		responseError, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read error response")
		}

		return nil, errors.Errorf("failed to register device: %s", responseError)
	}

	var device Device
	err = json.NewDecoder(response.Body).Decode(&device)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal device info")
	}
	logger = logger.WithField("device", device)
	logger.Trace("Device created")

	device.Token = token
	device.logger = logger

	return &device, nil
}
