// PROTOTYPE CODE - throwaway PoC, not production.
package main

import "time"

// claimGCInterval is how often the broker collects expired claim files after
// the pass at start.
const claimGCInterval = time.Hour

// startClaimGC runs the start-up pass (the caller opens no socket before it
// returns) and starts the hourly loop.
func startClaimGC(claims *ClaimStore, log *Logger, interval time.Duration, stop <-chan struct{}) {
	runClaimGC(claims, log)
	go claimGCLoop(claims, log, interval, stop)
}

// runClaimGC runs one collection pass and logs claim_gc with the number of
// removed files, plus claim_gc_skipped for every file it left in place.
func runClaimGC(claims *ClaimStore, log *Logger) {
	removed, skipped, err := claims.GC()
	ev := map[string]any{"removed": removed, "skipped": len(skipped)}
	if err != nil {
		ev["error"] = err.Error()
	}
	for _, sk := range skipped {
		log.Event("claim_gc_skipped", map[string]any{"file": sk.File, "error": sk.Error})
	}
	log.Event("claim_gc", ev)
}

// claimGCLoop repeats runClaimGC every interval until stop is closed (nil
// runs for the life of the process).
func claimGCLoop(claims *ClaimStore, log *Logger, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			runClaimGC(claims, log)
		case <-stop:
			return
		}
	}
}
