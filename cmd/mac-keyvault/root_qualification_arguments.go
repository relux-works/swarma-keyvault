package main

import (
	"errors"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

var errRootQualification = errors.New("public marker qualification refused")

// Set only by the matched qualification builder after validating the actual
// clean source objects. Empty/dev builds cannot admit owning qualification.
var rootQualificationSourceHead string
var rootQualificationSourceTree string

type rootQualificationCase uint8

const (
	rootQualificationCreate rootQualificationCase = iota + 1
	rootQualificationRead
	rootQualificationForeign
	rootQualificationHelper
	rootQualificationCleanup
)

type rootQualificationArguments struct {
	operation     rootQualificationCase
	receiptSHA256 string
}

// Parent cases are an exact positive argv allowlist, separate from the one
// foreign child invocation. No flag parser admits aliases, reordering, extra
// values, namespace/ref sources, arbitrary paths or alternate role policies.
func parseRootQualificationArguments(args []string) (rootQualificationArguments, error) {
	if len(args) != 5 && len(args) != 7 {
		return rootQualificationArguments{}, errRootQualification
	}
	if args[0] != "--json" || args[1] != "root-grants" || args[2] != "qualify-storage" || args[3] != "--case" {
		return rootQualificationArguments{}, errRootQualification
	}
	var operation rootQualificationCase
	switch args[4] {
	case "create-project":
		operation = rootQualificationCreate
	case "read-project":
		operation = rootQualificationRead
	case "foreign-read":
		operation = rootQualificationForeign
	case "helper-read":
		operation = rootQualificationHelper
	case "cleanup-created":
		operation = rootQualificationCleanup
	default:
		return rootQualificationArguments{}, errRootQualification
	}
	if operation == rootQualificationCreate {
		if len(args) != 5 {
			return rootQualificationArguments{}, errRootQualification
		}
		return rootQualificationArguments{operation: operation}, nil
	}
	if len(args) != 7 || args[5] != "--receipt-sha256" {
		return rootQualificationArguments{}, errRootQualification
	}
	if rootqualification.ValidateReceiptDigest(args[6]) != nil {
		return rootQualificationArguments{}, errRootQualification
	}
	return rootQualificationArguments{operation: operation, receiptSHA256: args[6]}, nil
}
