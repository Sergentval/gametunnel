package gatestate_test

import (
	"testing"

	"github.com/Sergentval/gametunnel/internal/gatestate"
	"github.com/Sergentval/gametunnel/internal/models"
)

func TestApplyEvent(t *testing.T) {
	cases := []struct {
		name     string
		from     models.GateState
		event    gatestate.Event
		wantTo   models.GateState
		wantEmit gatestate.Effect
	}{
		{"unknown+running=running", models.GateUnknown, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateRunning}, models.GateRunning, gatestate.EffectAddPort},
		{"unknown+stopped=stopped", models.GateUnknown, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateStopped}, models.GateStopped, gatestate.EffectNone},
		{"running+running=running", models.GateRunning, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateRunning}, models.GateRunning, gatestate.EffectNone},
		{"running+stopped=stopped_debounced", models.GateRunning, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateStopped}, models.GateRunning, gatestate.EffectArmDebounce},
		{"stopped+running=running_immediate", models.GateStopped, gatestate.Event{Kind: gatestate.EvStateUpdate, State: models.GateRunning}, models.GateRunning, gatestate.EffectAddPort},
		{"running+suspend=suspended", models.GateRunning, gatestate.Event{Kind: gatestate.EvSuspend}, models.GateSuspended, gatestate.EffectRemovePort},
		{"stopped+suspend=suspended", models.GateStopped, gatestate.Event{Kind: gatestate.EvSuspend}, models.GateSuspended, gatestate.EffectNone},
		{"suspended+unsuspend=unknown", models.GateSuspended, gatestate.Event{Kind: gatestate.EvUnsuspend}, models.GateUnknown, gatestate.EffectNone},
		{"running+debounce_fire=stopped", models.GateRunning, gatestate.Event{Kind: gatestate.EvDebounceFire, State: models.GateStopped}, models.GateStopped, gatestate.EffectRemovePort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotTo, gotEff := gatestate.Apply(c.from, c.event)
			if gotTo != c.wantTo {
				t.Errorf("to: got %q want %q", gotTo, c.wantTo)
			}
			if gotEff != c.wantEmit {
				t.Errorf("effect: got %q want %q", gotEff, c.wantEmit)
			}
		})
	}
}
