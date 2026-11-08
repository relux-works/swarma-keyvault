//go:build !linux && !darwin

package main

func sanitizeInheritedFDs() error { return refused }
