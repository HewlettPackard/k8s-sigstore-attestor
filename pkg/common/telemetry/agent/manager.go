package agent

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartManagerFetchEntriesUpdatesCall returns metric for when agent's
// synchronization manager fetching latest entries information
// from server
func StartManagerFetchEntriesUpdatesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Manager, telemetry.Sync, telemetry.FetchEntriesUpdates)
}

// StartManagerFetchSVIDsUpdatesCall returns metric for when agent's
// synchronization manager fetching latest SVIDs information
// from server
func StartManagerFetchSVIDsUpdatesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Manager, telemetry.Sync, telemetry.FetchSVIDsUpdates)
}

// End Call Counters

// Add Samples (metric on count of some object, entries, event...)

// AddCacheManagerExpiredSVIDsSample count of expiring SVIDs according to
// agent cache manager
func AddCacheManagerExpiredSVIDsSample(m telemetry.Metrics, cacheType string, count float32) {
	key := []string{telemetry.CacheManager, cacheType, telemetry.ExpiringSVIDs}
	if cacheType != "" {
		key = append(key, cacheType)
	}
	m.AddSample(key, count)
}

// AddCacheManagerOutdatedSVIDsSample count of SVIDs with outdated attributes
// according to agent cache manager
func AddCacheManagerOutdatedSVIDsSample(m telemetry.Metrics, cacheType string, count float32) {
	key := []string{telemetry.CacheManager, telemetry.OutdatedSVIDs}
	if cacheType != "" {
		key = append(key, cacheType)
	}
	m.AddSample(key, count)
}

// End Add Samples
