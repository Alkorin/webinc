package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

type KMS struct {
	device       *Device
	mercury      *Mercury
	cluster      string
	publicKey    *jose.JSONWebKey
	ephemeralKey *jose.JSONWebKey

	keys      map[string]*jose.JSONWebKey
	keysMutex sync.RWMutex

	pendingEvents      map[string]chan<- []byte
	pendingEventsMutex sync.RWMutex

	logger *log.Entry
}

type KmsRequest struct {
	URI    string `json:"uri"`
	Method string `json:"method"`
	Client struct {
		ClientId   string `json:"clientId"`
		Credential struct {
			UserId string `json:"userId"`
			Bearer string `json:"bearer"`
		} `json:"credential"`
	} `json:"client"`
	RequestId string           `json:"requestId"`
	JWK       *jose.JSONWebKey `json:"jwk,omitempty"`
	Count     int              `json:"count,omitempty"`
	KeyUris   []string         `json:"keyUris,omitempty"`
}

type KmsBatchRequest struct {
	Destination string   `json:"destination"`
	KmsMessages []string `json:"kmsMessages"`
}

func (k *KmsRequest) Encrypt(key *jose.JSONWebKey) (string, error) {
	data, err := json.Marshal(k)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal request")
	}

	return EncryptWithKey(data, key)
}

func NewKMS(device *Device, mercury *Mercury) (*KMS, error) {
	kms := &KMS{
		device:        device,
		mercury:       mercury,
		keys:          make(map[string]*jose.JSONWebKey),
		pendingEvents: make(map[string]chan<- []byte),
		logger:        log.WithField("type", "KMS"),
	}
	mercury.RegisterHandler("encryption.kms_message", kms.ParseMercuryEncryptionMessage)

	// Request KMS StaticPubKey
	kms.logger.Trace("Request public key")
	responsePubKey, err := device.RequestService("GET", "encryptionServiceUrl", "/kms/"+device.UserID, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request KMS static public key")
	}
	defer responsePubKey.Body.Close()

	if responsePubKey.StatusCode != http.StatusOK {
		responseError, err := ioutil.ReadAll(responsePubKey.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read error response")
		}

		return nil, errors.Errorf("failed to request KMS static public key: %s", responseError)
	}

	// Parse response
	var kmsInfos struct {
		KmsCluster   string
		RsaPublicKey string
	}

	err = json.NewDecoder(responsePubKey.Body).Decode(&kmsInfos)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal KMS infos")
	}
	kms.cluster = kmsInfos.KmsCluster

	// Parse PublicKey
	var key jose.JSONWebKey
	err = key.UnmarshalJSON([]byte(kmsInfos.RsaPublicKey))
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal KMS public key")
	}

	kms.publicKey = kms.RegisterKey(key.KeyID, key)

	// Generate ECDHE key
	localEcdhKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate local ecdsa key")
	}

	// Send PublicKey to KMS
	kmsKeyRequest := KmsRequest{
		URI:       kmsInfos.KmsCluster + "/ecdhe",
		Method:    "create",
		JWK:       &jose.JSONWebKey{Key: localEcdhKey.Public()},
		RequestId: uuid.Must(uuid.NewV4()).String(),
	}
	kmsKeyRequest.Client.ClientId = device.Url
	kmsKeyRequest.Client.Credential.UserId = device.UserID
	kmsKeyRequest.Client.Credential.Bearer = device.Token

	kms.logger.Trace("Send public local ecdsa key")
	resp, err := kms.SendRequest(kmsInfos.KmsCluster, kms.publicKey, kmsKeyRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send local ecdsa key")
	}

	kms.logger.Trace("Received remote ecdsa key")
	var kmsEcdhMessage struct {
		Key struct {
			Uri string
			Jwk jose.JSONWebKey
		}
	}
	err = json.Unmarshal(resp, &kmsEcdhMessage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal kms response")
	}

	remoteEcdhKey, ok := kmsEcdhMessage.Key.Jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid remote ecdh key")
	}

	// Compute shared key
	x, _ := remoteEcdhKey.Curve.ScalarMult(remoteEcdhKey.X, remoteEcdhKey.Y, localEcdhKey.D.Bytes())
	k := make([]byte, 32)
	hkdf.New(sha256.New, x.Bytes(), nil, nil).Read(k)
	sharedKey := jose.JSONWebKey{KeyID: kmsEcdhMessage.Key.Uri, Key: k}

	kms.ephemeralKey = kms.RegisterKey(kmsEcdhMessage.Key.Uri, sharedKey)

	return kms, nil
}

func (k *KMS) RegisterKey(kid string, key jose.JSONWebKey) *jose.JSONWebKey {
	k.keysMutex.Lock()
	k.keys[kid] = &key
	k.keysMutex.Unlock()

	return &key
}

func (k *KMS) GetKey(kid string) (*jose.JSONWebKey, error) {
	logger := k.logger.WithField("func", "GetKey").WithField("kid", kid)
	logger.Trace("Request key")

	k.keysMutex.RLock()
	if key, ok := k.keys[kid]; ok {
		logger.Trace("Found in cache")
		k.keysMutex.RUnlock()
		return key, nil
	}
	k.keysMutex.RUnlock()

	// Not found, request key to KMS
	kmsRequest := KmsRequest{
		URI:       kid,
		Method:    "retrieve",
		RequestId: uuid.Must(uuid.NewV4()).String(),
	}
	kmsRequest.Client.ClientId = k.device.Url
	kmsRequest.Client.Credential.UserId = k.device.UserID
	kmsRequest.Client.Credential.Bearer = k.device.Token

	logger.Trace("Fetch key")
	resp, err := k.SendRequest(k.cluster, k.ephemeralKey, kmsRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send key request")
	}

	logger.Trace("Received key")

	var kmsKey struct {
		Key struct {
			Uri string
			Jwk jose.JSONWebKey
		}
	}

	err = json.Unmarshal(resp, &kmsKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal kms key response")
	}

	key := k.RegisterKey(kmsKey.Key.Uri, kmsKey.Key.Jwk)
	return key, nil
}

func (k *KMS) CreateKey() (*jose.JSONWebKey, error) {
	logger := k.logger.WithField("func", "CreateKey")
	logger.Trace("Create key")

	kmsRequest := KmsRequest{
		URI:       "/keys",
		Method:    "create",
		RequestId: uuid.Must(uuid.NewV4()).String(),
		Count:     1,
	}
	kmsRequest.Client.ClientId = k.device.Url
	kmsRequest.Client.Credential.UserId = k.device.UserID
	kmsRequest.Client.Credential.Bearer = k.device.Token

	resp, err := k.SendRequest(k.cluster, k.ephemeralKey, kmsRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send key request")
	}

	logger.Trace("Received key")

	var kmsKeys struct {
		Keys []struct {
			Uri string
			Jwk jose.JSONWebKey
		}
	}

	err = json.Unmarshal(resp, &kmsKeys)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal kms key response")
	}

	if len(kmsKeys.Keys) != 1 {
		return nil, errors.Wrap(err, "wrong number of key received")
	}

	key := k.RegisterKey(kmsKeys.Keys[0].Uri, kmsKeys.Keys[0].Jwk)
	return key, nil
}

func (k *KMS) CreateDeferredHandler(name string) <-chan []byte {
	k.pendingEventsMutex.Lock()
	defer k.pendingEventsMutex.Unlock()

	c := make(chan []byte, 1)
	k.pendingEvents[name] = c
	return c
}

func (k *KMS) GetDeferredHandler(name string) chan<- []byte {
	k.pendingEventsMutex.Lock()
	defer k.pendingEventsMutex.Unlock()

	if c, ok := k.pendingEvents[name]; ok {
		delete(k.pendingEvents, name)
		return c
	}

	return nil
}

func (k *KMS) SendRequest(cluster string, key *jose.JSONWebKey, request KmsRequest) ([]byte, error) {
	logger := k.logger.WithField("func", "SendRequest")
	encryptedRequest, err := request.Encrypt(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt request")
	}

	batchRequestJson, err := json.Marshal(KmsBatchRequest{
		Destination: cluster,
		KmsMessages: []string{encryptedRequest},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal request")
	}

	waitingChan := k.CreateDeferredHandler(request.RequestId)
	logger.Trace("Send KMS Request")
	httpResponse, err := k.device.RequestService("POST", "encryptionServiceUrl", "/kms/messages", bytes.NewReader(batchRequestJson))
	if err != nil {
		return nil, errors.Wrap(err, "failed to send kms http request")
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusAccepted {
		responseError, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read error response")
		}
		return nil, errors.Errorf("failed to send request to KMS: %s", responseError)
	}

	kmsResponse := <-waitingChan
	return kmsResponse, nil
}

func (k *KMS) NewResourceCreateMessage(keys ...*jose.JSONWebKey) (string, error) {
	kmsRequest := KmsRequest{
		URI:    "/resources",
		Method: "create",
	}

	for _, v := range keys {
		kmsRequest.KeyUris = append(kmsRequest.KeyUris, v.KeyID)
	}

	kmsRequest.Client.ClientId = k.device.Url
	kmsRequest.Client.Credential.UserId = k.device.UserID
	kmsRequest.Client.Credential.Bearer = k.device.Token

	return kmsRequest.Encrypt(k.ephemeralKey)
}

func (k *KMS) ParseMercuryEncryptionMessage(msg []byte) {
	logger := k.logger.WithField("func", "ParseMercuryEncryptionMessage").WithField("msg", string(msg))

	var mercuryEncryptionKmsMessage MercuryEncryptionKmsMessage
	err := json.Unmarshal(msg, &mercuryEncryptionKmsMessage)
	if err != nil {
		logger.WithError(err).Errorf("Failed to unmarshal MercuryEncryptionKmsMessage")
		return
	}

	for _, message := range mercuryEncryptionKmsMessage.Data.Encryption.KmsMessages {
		logger.Trace("Parsing message")
		switch strings.Count(message, ".") {
		case 2:
			// Parse Signed Message
			jws, err := jose.ParseSigned(message)
			if err != nil {
				logger.WithError(err).Error("Failed to parse signed message")
				continue
			}

			// Extract kid
			kid := jws.Signatures[0].Header.KeyID
			logger = logger.WithField("kid", kid)

			key, err := k.GetKey(kid)
			if err != nil {
				logger.WithError(err).Error("Failed to get key")
				continue
			}

			payload, err := jws.Verify(key)
			if err != nil {
				log.WithError(err).Error("Invalid signature")
				continue
			}

			logger = logger.WithField("payload", string(payload))
			logger.Trace("Message verified")

			// Extract reqId
			var reqId struct {
				RequestId string
			}
			err = json.Unmarshal(payload, &reqId)
			if err != nil {
				logger.WithError(err).Error("Failed to extract RequestId")
				continue
			}
			logger = logger.WithField("requestId", reqId.RequestId)

			c := k.GetDeferredHandler(reqId.RequestId)
			if c != nil {
				log.Trace("Message sent to deferred handler")
				c <- payload
				close(c)
			} else {
				logger.Error("Unknown deferred event")
			}
		case 4:
			jwe, err := jose.ParseEncrypted(message)
			if err != nil {
				logger.WithError(err).Error("Failed to parse encrypted message")
				continue
			}
			kid := jwe.Header.KeyID
			logger = logger.WithField("kid", kid)

			key, err := k.GetKey(kid)
			if err != nil {
				logger.WithError(err).Error("Failed to get key")
				continue
			}

			payload, err := jwe.Decrypt(key)
			logger = logger.WithField("payload", string(payload))
			logger.Trace("Message decrypted")

			// Extract reqId
			var reqId struct {
				RequestId string
			}
			err = json.Unmarshal(payload, &reqId)
			if err != nil {
				logger.WithError(err).Error("Failed to extract RequestId")
				continue
			}
			logger = logger.WithField("requestId", reqId.RequestId)

			c := k.GetDeferredHandler(reqId.RequestId)
			if c != nil {
				log.Trace("Message sent to deferred handler")
				c <- payload
				close(c)
			} else {
				logger.Error("Unknown deferred event")
			}
		default:
			logger.Error("Invalid message")
		}
	}
}

func (k *KMS) Encrypt(data []byte, keyUrl string) (string, error) {
	key, err := k.GetKey(keyUrl)
	if err != nil {
		return "", errors.Wrap(err, "failed to fetch encryption key")
	}

	return EncryptWithKey(data, key)
}

func (k *KMS) Decrypt(data string, keyUrl string) ([]byte, error) {
	key, err := k.GetKey(keyUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch encryption key")
	}
	return DecryptWithKey(data, key)
}

func EncryptWithKey(data []byte, key *jose.JSONWebKey) (string, error) {
	alg := jose.DIRECT
	if _, ok := key.Key.(*rsa.PublicKey); ok {
		alg = jose.RSA_OAEP
	}

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: alg, Key: key}, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create jose encrypter")
	}

	object, err := encrypter.Encrypt(data)
	if err != nil {
		return "", errors.Wrap(err, "failed to encrypt kms request")
	}

	return object.CompactSerialize()
}

func DecryptWithKey(data string, key *jose.JSONWebKey) ([]byte, error) {
	encryptedObject, err := jose.ParseEncrypted(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse encrypted message")
	}

	plain, err := encryptedObject.Decrypt(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt message")
	}

	return plain, nil
}
