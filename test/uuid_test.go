package main

import "github.com/gofrs/uuid/v5"

func newUUID() uuid.UUID {
	return uuid.Must(uuid.NewV4())
}
