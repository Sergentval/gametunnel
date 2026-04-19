// Package gatestate implements the per-tunnel container-state-aware gating
// state machine for GameTunnel. It owns decisions about when a port should
// be in the nftables game_ports set, based on signals from the home agent's
// Docker event watcher and the Pelican panel reconciler.
//
// This file is pure logic: no timers, no locks, no I/O. Transitions are
// total functions of (current state, event) → (next state, effect).
package gatestate

import "github.com/Sergentval/gametunnel/internal/models"

// EventKind classifies the cause of a state update.
type EventKind int

const (
	EvStateUpdate   EventKind = iota // agent-reported container state
	EvSuspend                        // panel: server suspended
	EvUnsuspend                      // panel: server unsuspended
	EvDebounceFire                   // debouncer timer expired
)

// Event is the input to the state machine.
type Event struct {
	Kind  EventKind
	State models.GateState // only used for EvStateUpdate and EvDebounceFire
}

// Effect is the side effect to enact after a transition. The state machine
// itself doesn't perform effects; manager.go does, based on the returned value.
type Effect string

const (
	EffectNone        Effect = "none"         // no nft change, no debounce change
	EffectAddPort     Effect = "add_port"     // add port to nft game_ports set
	EffectRemovePort  Effect = "remove_port"  // remove port from nft game_ports set
	EffectArmDebounce Effect = "arm_debounce" // start 120s timer for running→stopped; current port membership unchanged
)

// Apply returns the next state and the effect to enact. Pure function.
func Apply(from models.GateState, e Event) (models.GateState, Effect) {
	switch e.Kind {
	case EvSuspend:
		if from == models.GateRunning {
			return models.GateSuspended, EffectRemovePort
		}
		return models.GateSuspended, EffectNone
	case EvUnsuspend:
		return models.GateUnknown, EffectNone
	case EvDebounceFire:
		// Fired after the 120s window expired without a reversing event.
		if e.State == models.GateStopped {
			return models.GateStopped, EffectRemovePort
		}
		return from, EffectNone
	case EvStateUpdate:
		switch e.State {
		case models.GateRunning:
			if from == models.GateRunning {
				return models.GateRunning, EffectNone
			}
			return models.GateRunning, EffectAddPort
		case models.GateStopped:
			if from == models.GateRunning {
				// debounce 120s before tear-down
				return models.GateRunning, EffectArmDebounce
			}
			if from == models.GateStopped {
				return models.GateStopped, EffectNone
			}
			// unknown or suspended → stopped (no port to remove since not currently in set)
			return models.GateStopped, EffectNone
		}
	}
	return from, EffectNone
}
