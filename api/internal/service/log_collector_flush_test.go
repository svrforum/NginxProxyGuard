package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestRecordFlushedByType_PerStreamTimestamps(t *testing.T) {
	c := &LogCollector{}
	c.recordFlushedByType([]model.CreateLogRequest{
		{LogType: model.LogTypeAccess},
		{LogType: model.LogTypeAccess},
		{LogType: model.LogTypeModSec},
	})

	if c.AccessLastFlushUnix() == 0 {
		t.Error("access last-flush should be set after flushing access logs")
	}
	if c.ModsecLastFlushUnix() == 0 {
		t.Error("modsec last-flush should be set after flushing modsec logs")
	}
	if c.ErrorLastFlushUnix() != 0 {
		t.Error("error last-flush should remain zero (no error logs flushed)")
	}
}
