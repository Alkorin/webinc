package main

import (
	"time"
)

type Activity struct {
	Verb      string
	Published time.Time
	Actor     struct {
		Id string
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
	}
	EncryptionKeyUrl string
}
