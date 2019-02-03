package main

type MercuryAuthRequest struct {
	Id   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

type MercuryAck struct {
	MessageId string `json:"messageId"`
	Type      string `json:"type"`
}

type MercuryMessage struct {
	Id   string
	Data struct {
		EventType string
	}
	SequenceNumber int
}

type MercuryEncryptionKmsMessage struct {
	Data struct {
		Encryption struct {
			KmsMessages []string
		}
	}
}

type MercuryConversationActivity struct {
	Data struct {
		Activity Activity
	}
}
