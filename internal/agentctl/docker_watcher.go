// Package agentctl docker_watcher subscribes to Docker events and emits
// ContainerStateUpdate messages to the GT server on every Pelican-managed
// container state transition (start/stop/die/restart).
package agentctl

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"github.com/Sergentval/gametunnel/internal/models"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsPelicanContainerName returns true when the container name matches a
// Pelican server UUID (lowercase). Docker names usually begin with "/" on the
// wire; we strip it before matching.
func IsPelicanContainerName(name string) bool {
	n := strings.TrimPrefix(name, "/")
	return uuidRE.MatchString(n)
}

// dockerStateFromEvent maps a Docker event Action to a container state string.
// Returns (state, true) for relevant actions; ("", false) otherwise.
func dockerStateFromEvent(action events.Action) (string, bool) {
	switch action {
	case events.ActionStart:
		return "running", true
	case events.ActionStop, events.ActionDie, events.ActionKill:
		return "stopped", true
	case events.ActionRestart:
		return "starting", true
	}
	return "", false
}

// DockerWatcher streams Docker container events, filters to Pelican UUIDs,
// and invokes emit on each relevant state transition.
type DockerWatcher struct {
	cli   *client.Client
	agent string
	emit  func(models.ContainerStateUpdate)
}

// NewDockerWatcher constructs a DockerWatcher.
func NewDockerWatcher(cli *client.Client, agentID string, emit func(models.ContainerStateUpdate)) *DockerWatcher {
	return &DockerWatcher{cli: cli, agent: agentID, emit: emit}
}

// Run blocks until ctx is done or the event stream errors.  The caller is
// responsible for restarting Run after a transient error (e.g. Docker daemon
// restart).
func (w *DockerWatcher) Run(ctx context.Context) error {
	f := filters.NewArgs(filters.Arg("type", string(events.ContainerEventType)))
	msgs, errs := w.cli.Events(ctx, events.ListOptions{Filters: f})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errs:
			slog.Warn("docker events stream error", "error", err)
			return err
		case m := <-msgs:
			name := ""
			if m.Actor.Attributes != nil {
				name = m.Actor.Attributes["name"]
			}
			if !IsPelicanContainerName(name) {
				continue
			}
			state, relevant := dockerStateFromEvent(m.Action)
			if !relevant {
				continue
			}
			w.emit(models.ContainerStateUpdate{
				Type:       "container.state_update",
				AgentID:    w.agent,
				ServerUUID: strings.TrimPrefix(name, "/"),
				State:      state,
				Timestamp:  time.Unix(m.Time, m.TimeNano),
				Cause:      string(m.Action),
			})
		}
	}
}

// Snapshot enumerates all current containers and returns a ContainerSnapshot.
// Call this on agent (re)connect to reconcile server-side state.
func (w *DockerWatcher) Snapshot(ctx context.Context) (models.ContainerSnapshot, error) {
	list, err := w.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return models.ContainerSnapshot{}, fmt.Errorf("list containers: %w", err)
	}
	out := models.ContainerSnapshot{
		Type:       "container.snapshot",
		AgentID:    w.agent,
		SnapshotAt: time.Now(),
	}
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}
		if !IsPelicanContainerName(name) {
			continue
		}
		state := "stopped"
		if c.State == "running" {
			state = "running"
		}
		out.Containers = append(out.Containers, models.ContainerSnapshotItem{
			ServerUUID: strings.TrimPrefix(name, "/"),
			State:      state,
		})
	}
	return out, nil
}

