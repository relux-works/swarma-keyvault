// Package grants contains local grant policy calculations. These predicates do
// not authenticate a certificate, qualify a clock, reserve a use or authorize an
// effect. Callers must establish those independent requirements before dispatch.
package grants

import (
	"errors"
	"time"
)

var (
	ErrInvalidInterval    = errors.New("grant validity endpoints must be increasing whole UTC seconds in years 1 through 9999")
	ErrLifetimeExceeded   = errors.New("grant validity exceeds its supported ten-calendar-year cap")
	ErrNotYetValid        = errors.New("grant validity has not started")
	ErrExpired            = errors.New("grant validity has expired")
	ErrInvalidObservation = errors.New("grant observation is outside supported years 1 through 9999")
)

// ValidateInterval checks already-decoded validity instants, not their wire
// spelling. Endpoints must be whole seconds, with a positive interval no longer
// than ten calendar years. A February 29 anniversary clamps to February 28.
// An anniversary beyond year 9999 is unsupported even for a shorter interval.
func ValidateInterval(notBefore, expiresAt time.Time) error {
	notBefore = notBefore.UTC()
	expiresAt = expiresAt.UTC()
	if !supportedYear(notBefore) || !supportedYear(expiresAt) || notBefore.Nanosecond() != 0 || expiresAt.Nanosecond() != 0 || !expiresAt.After(notBefore) {
		return ErrInvalidInterval
	}
	year := notBefore.Year() + 10
	if year > 9999 {
		return ErrLifetimeExceeded
	}
	month, day := notBefore.Month(), notBefore.Day()
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > lastDay {
		day = lastDay
	}
	cap := time.Date(year, month, day, notBefore.Hour(), notBefore.Minute(), notBefore.Second(), 0, time.UTC)
	if expiresAt.After(cap) {
		return ErrLifetimeExceeded
	}
	return nil
}

// CheckIntervalAt evaluates [notBefore, expiresAt) at a supplied observation.
// It reads no clock and applies no skew, rounding or rollback correction.
// Subsecond observations remain exact. UTC conversion preserves the instant;
// canonical timestamp decoding and trusted clock/state continuity are separate.
func CheckIntervalAt(notBefore, expiresAt, observedAt time.Time) error {
	if err := ValidateInterval(notBefore, expiresAt); err != nil {
		return err
	}
	observedAt = observedAt.UTC()
	if !supportedYear(observedAt) {
		return ErrInvalidObservation
	}
	if observedAt.Before(notBefore.UTC()) {
		return ErrNotYetValid
	}
	if !observedAt.Before(expiresAt.UTC()) {
		return ErrExpired
	}
	return nil
}

func supportedYear(value time.Time) bool {
	return value.Year() >= 1 && value.Year() <= 9999
}
