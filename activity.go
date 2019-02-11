package main

import (
	"time"
)

type Activity struct {
	Id        string
	Verb      string
	Published time.Time
	Actor     struct {
		Id          string
		DisplayName string
		EntryUUID   string
	}
	Target struct {
		Url string
		Id  string
	}
	Object struct {
		Id          string
		DisplayName string
		Mentions    struct {
			Items []struct {
				Id string
			}
		}
		ContentCategory string
	}
	EncryptionKeyUrl string
}
