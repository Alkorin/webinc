package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

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
	config *Config
}

func NewDevice(config *Config) (*Device, error) {
	logger := log.WithField("type", "Device")

	token := config.GetString("auth-token")
	for token == "" {
		fmt.Println("Please provide a valid auth-token associated to your Webex Teams account. To obtain one, you can go to https://developer.webex.com/login, Documentation, Api Reference, choose any API endpoint and you will be able to copy the Authorization token on the right.")
		fmt.Print("token> ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		token = scanner.Text()
	}

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

	// Keep values
	device.Token = token
	device.logger = logger
	device.config = config

	// Store in config
	config.SetString("auth-token", token)
	config.Save()

	return &device, nil
}

func (d *Device) RequestService(method string, service string, url string, data io.Reader) (*http.Response, error) {
	httpRequest, err := http.NewRequest(method, d.Services[service]+url, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create kms http request")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+d.Token)
	httpRequest.Header.Set("Content-type", "application/json")

	return http.DefaultClient.Do(httpRequest)
}
