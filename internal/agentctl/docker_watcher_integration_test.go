//go:build integration
// +build integration

package agentctl_test

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	dockerclient "github.com/docker/docker/client"

	"github.com/Sergentval/gametunnel/internal/agentctl"
	"github.com/Sergentval/gametunnel/internal/models"
)

const (
	testUUID  = "11111111-2222-3333-4444-555555555555"
	testImage = "alpine:3"
	testCmd   = "sleep 60"
)

// dockerAvailable returns a Docker client or skips the test if Docker is unreachable.
func dockerAvailable(t *testing.T) *dockerclient.Client {
	t.Helper()
	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Skipf("docker client init failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Ping(ctx); err != nil {
		cli.Close()
		t.Skipf("docker daemon unreachable: %v", err)
	}
	return cli
}

// ensureImage pulls the image if it's not already present locally.
func ensureImage(t *testing.T, cli *dockerclient.Client, ref string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rc, err := cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		t.Skipf("cannot pull image %s: %v", ref, err)
	}
	// Drain the response so the pull completes before we proceed.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		t.Logf("warning: draining image pull response: %v", err)
	}
	rc.Close()
}

// removeContainer removes a container by ID, ignoring errors (used in cleanup).
func removeContainer(cli *dockerclient.Client, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = cli.ContainerRemove(ctx, id, container.RemoveOptions{Force: true})
}

// collectEvents returns a thread-safe emit function and a getter for the
// accumulated slice. The getter returns a shallow copy to avoid data races.
func collectEvents() (emit func(models.ContainerStateUpdate), get func() []models.ContainerStateUpdate) {
	var mu sync.Mutex
	var events []models.ContainerStateUpdate
	emit = func(msg models.ContainerStateUpdate) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, msg)
	}
	get = func() []models.ContainerStateUpdate {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]models.ContainerStateUpdate, len(events))
		copy(cp, events)
		return cp
	}
	return emit, get
}

// waitForState polls the event getter until an event matching uuid+state is
// found, or until timeout elapses.
func waitForState(t *testing.T, get func() []models.ContainerStateUpdate, uuid, state string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, e := range get() {
			if e.ServerUUID == uuid && e.State == state {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("timed out after %s waiting for %q event for uuid %s", timeout, state, uuid)
}

// startWatcher starts a DockerWatcher goroutine and returns a teardown function
// that cancels the context and waits for the goroutine to finish.
func startWatcher(t *testing.T, cli *dockerclient.Client, emit func(models.ContainerStateUpdate)) (teardown func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	watcher := agentctl.NewDockerWatcher(cli, "test-agent", emit)
	go func() {
		defer close(done)
		_ = watcher.Run(ctx)
	}()
	// Give the events subscription a moment to establish before producing events.
	time.Sleep(500 * time.Millisecond)
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Log("watcher did not exit cleanly within 3s")
		}
	}
}

// TestDockerWatcher_StartStopEvents_Integration verifies that starting and
// stopping a UUID-named container emits the expected ContainerStateUpdate messages.
func TestDockerWatcher_StartStopEvents_Integration(t *testing.T) {
	cli := dockerAvailable(t)
	defer cli.Close()
	ensureImage(t, cli, testImage)

	emit, get := collectEvents()
	teardown := startWatcher(t, cli, emit)
	defer teardown()

	ctx := context.Background()

	// Create a UUID-named container (Pelican-compatible name).
	createResp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: testImage,
			Cmd:   []string{"sh", "-c", testCmd},
		},
		nil, nil, nil, testUUID,
	)
	if err != nil {
		t.Fatalf("container create: %v", err)
	}
	t.Cleanup(func() { removeContainer(cli, createResp.ID) })

	// Start the container.
	if err := cli.ContainerStart(ctx, createResp.ID, container.StartOptions{}); err != nil {
		t.Fatalf("container start: %v", err)
	}

	// Expect a "running" event.
	waitForState(t, get, testUUID, "running", 5*time.Second)

	// Stop the container.
	stopTimeout := 1
	if err := cli.ContainerStop(ctx, createResp.ID, container.StopOptions{Timeout: &stopTimeout}); err != nil {
		t.Fatalf("container stop: %v", err)
	}

	// Expect a "stopped" event.
	waitForState(t, get, testUUID, "stopped", 5*time.Second)
}

// TestDockerWatcher_Snapshot_Integration verifies that Snapshot returns the
// running test container with state "running".
func TestDockerWatcher_Snapshot_Integration(t *testing.T) {
	cli := dockerAvailable(t)
	defer cli.Close()
	ensureImage(t, cli, testImage)

	ctx := context.Background()

	createResp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: testImage,
			Cmd:   []string{"sh", "-c", testCmd},
		},
		nil, nil, nil, testUUID,
	)
	if err != nil {
		t.Fatalf("container create: %v", err)
	}
	t.Cleanup(func() { removeContainer(cli, createResp.ID) })

	if err := cli.ContainerStart(ctx, createResp.ID, container.StartOptions{}); err != nil {
		t.Fatalf("container start: %v", err)
	}

	// Small delay so Docker's internal state settles before Snapshot.
	time.Sleep(200 * time.Millisecond)

	emit, _ := collectEvents()
	watcher := agentctl.NewDockerWatcher(cli, "test-agent", emit)

	snap, err := watcher.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	found := false
	for _, item := range snap.Containers {
		if item.ServerUUID == testUUID {
			found = true
			if item.State != "running" {
				t.Errorf("snapshot: container %s state = %q, want %q", testUUID, item.State, "running")
			}
			break
		}
	}
	if !found {
		t.Errorf("snapshot: container %s not found in snapshot (got %d items)", testUUID, len(snap.Containers))
	}
}

// TestDockerWatcher_IgnoresNonUUIDContainer_Integration verifies that a
// container with a non-UUID name does not produce any ContainerStateUpdate.
func TestDockerWatcher_IgnoresNonUUIDContainer_Integration(t *testing.T) {
	cli := dockerAvailable(t)
	defer cli.Close()
	ensureImage(t, cli, testImage)

	emit, get := collectEvents()
	teardown := startWatcher(t, cli, emit)
	defer teardown()

	ctx := context.Background()

	// Use a clearly non-UUID name.
	const ignoredName = "gt-integration-test-ignored"
	createResp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: testImage,
			Cmd:   []string{"sh", "-c", testCmd},
		},
		nil, nil, nil, ignoredName,
	)
	if err != nil {
		t.Fatalf("container create: %v", err)
	}
	t.Cleanup(func() { removeContainer(cli, createResp.ID) })

	if err := cli.ContainerStart(ctx, createResp.ID, container.StartOptions{}); err != nil {
		t.Fatalf("container start: %v", err)
	}

	// Wait long enough that a spurious event would have arrived.
	time.Sleep(1 * time.Second)

	// Verify no event was emitted for the non-UUID container.
	for _, e := range get() {
		if e.ServerUUID == ignoredName {
			t.Errorf("unexpected event emitted for non-UUID container %q: %+v", ignoredName, e)
		}
	}
}
