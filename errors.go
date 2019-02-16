package main

import (
	"github.com/pkg/errors"
)

var ErrInvalidToken = errors.New("token is invalid")
var ErrInvalidDevice = errors.New("device is invalid")
