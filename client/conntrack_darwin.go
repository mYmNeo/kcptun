//go:build darwin

package main

import "errors"

func NewConntrackFlow() (ConntrackLookup, error) {
	return nil, errors.New("not implemented")
}
