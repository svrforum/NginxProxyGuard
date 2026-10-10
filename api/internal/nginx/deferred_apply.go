package nginx

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// DeferredStep is a config step startup runs against nginx. Apply renders its
// files from the settings as they are when it runs, validates them with
// nginx -t and rolls them back when the test fails, as GenerateMainNginxConfig
// and GenerateFilterSubscriptionConfigs do.
type DeferredStep struct {
	Name  string
	Apply func(ctx context.Context) error
}

// DeferredSteps keeps the startup steps that failed only because the nginx
// container was not running. On an upgrade compose recreates the API first
// and starts nginx after it, so nginx -t cannot run at boot and each step's
// rollback leaves the previous release's file in place, which nginx then
// starts on. ApplyWhenUp runs the kept steps again once nginx is up.
type DeferredSteps struct {
	steps []DeferredStep
}

// Run runs step now and keeps it when it failed because nginx is not
// running. Any other error, such as nginx rejecting the result, is final, as
// for every other save.
func (d *DeferredSteps) Run(ctx context.Context, step DeferredStep) (deferred bool, err error) {
	err = step.Apply(ctx)
	if IsNginxUnreachableError(err) {
		d.steps = append(d.steps, step)
		return true, err
	}
	return false, err
}

// Steps returns the kept steps in the order they ran.
func (d *DeferredSteps) Steps() []DeferredStep {
	return d.steps
}

// deferredApplyTimeout bounds one pass over the steps plus the reload once
// nginx is up; each step runs its own nginx -t (config.NginxTestTimeout).
const deferredApplyTimeout = 5 * time.Minute

// nginxNotStartedPattern matches nginx -s reload in a container whose nginx
// has not started yet: there is no master process, so no pid to signal.
var nginxNotStartedPattern = regexp.MustCompile(`nginx\.pid" failed|invalid PID number`)

// notUpYet reports whether err means nginx is not up yet (container not
// running, or nginx in it not started), so the steps are to run again later.
func notUpYet(err error) bool {
	return err != nil && (IsNginxUnreachableError(err) || nginxNotStartedPattern.MatchString(err.Error()))
}

// ApplyWhenUp waits for nginx to come up, then runs steps again in order and
// reloads nginx once. It checks every poll and gives up after wait; ctx, the
// API's lifetime, stops it at once.
//
// Each step validates its own result, so nothing untested is left on disk. A
// step nginx rejects is final: the error is returned and nothing retries it.
// If nginx turns out not to be up after all (gone again, or not started yet),
// every step runs again once it is.
func (m *Manager) ApplyWhenUp(ctx context.Context, steps []DeferredStep, poll, wait time.Duration) error {
	if len(steps) == 0 {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	var notUp error // why nginx was not up at the last check
	for {
		select {
		case <-waitCtx.Done():
			if err := ctx.Err(); err != nil {
				return err
			}
			if notUp == nil {
				return fmt.Errorf("nginx did not come up within %v", wait)
			}
			return fmt.Errorf("nginx did not come up within %v (last check: %w)", wait, notUp)
		case <-ticker.C:
		}
		if err := m.upForDeferredSteps(waitCtx); err != nil {
			if waitCtx.Err() == nil { // a check cut short by the deadline says nothing
				notUp = err
			}
			continue
		}
		err := m.applyDeferredSteps(ctx, steps)
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if notUpYet(err) {
			notUp = err
			continue
		}
		return err
	}
}

// upForDeferredSteps returns nil once nginx can take the steps, else why not.
// Answering docker exec is not enough: the nginx entrypoint still refreshes
// files in the shared volume before it starts nginx, and a reload needs
// nginx's master process. So, unless the post-reload health probe is switched
// off, it also waits for nginx's worker processes.
func (m *Manager) upForDeferredSteps(ctx context.Context) error {
	if err := m.TestConfig(ctx); err != nil && (IsNginxUnreachableError(err) || ctx.Err() != nil) {
		return err
	}
	if p := m.healthProber; p != nil && !p.disabled {
		// pgrep, not countWorkers: countWorkers greps ps inside `sh -c`,
		// whose own command line holds the pattern, so it never reads zero.
		if _, err := p.exec.Exec(ctx, "pgrep", "-f", "nginx: worker"); err != nil {
			return fmt.Errorf("nginx has not started its workers yet: %w", err)
		}
	}
	return nil
}

// applyDeferredSteps runs steps in order and then reloads nginx once, unless
// every step failed (each failed step has already rolled itself back). As at
// boot, a step nginx rejects does not stop the ones after it. A step or reload
// that finds nginx not up yet returns that error alone, for ApplyWhenUp to
// wait and run every step again.
func (m *Manager) applyDeferredSteps(parent context.Context, steps []DeferredStep) error {
	ctx, cancel := context.WithTimeout(parent, deferredApplyTimeout)
	defer cancel()

	var failed []error
	for _, s := range steps {
		if err := s.Apply(ctx); err != nil {
			if notUpYet(err) {
				return err
			}
			failed = append(failed, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	if len(failed) == len(steps) {
		return errors.Join(failed...)
	}
	if err := m.TestAndReload(ctx); err != nil {
		if notUpYet(err) {
			return err
		}
		failed = append(failed, fmt.Errorf("reload: %w", err))
	}
	return errors.Join(failed...)
}
