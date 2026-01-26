//go:build darwin

package main

import "errors"

func NewConntrackFlow(filters []ConnTupleKeyFilter) (ConntrackLookup, error) {
	return nil, errors.New("not implemented")
}
