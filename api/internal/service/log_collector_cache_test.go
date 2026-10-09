package service

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/cache"
)

// Every persisted CreateLogRequest field must survive the Valkey buffer:
// toCacheLogEntry -> JSON (as Valkey stores it) -> fromCacheLogEntry. A field
// added to the request but not to both mappings is silently stored as NULL
// whenever Valkey is up, which is how rule_data went missing.
func TestCacheLogEntryRoundTrip(t *testing.T) {
	in := model.CreateLogRequest{LogType: model.LogTypeModSec}
	v := reflect.ValueOf(&in).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch name := v.Type().Field(i).Name; name {
		case "LogType", "WAFEngineBlocking": // fixed above / never persisted (json:"-")
		case "BlockReason":
			f.SetString(string(model.BlockReasonWAF))
		case "Severity":
			f.SetString(string(model.LogSeverityError))
		default:
			switch f.Kind() {
			case reflect.String:
				f.SetString("v-" + name)
			case reflect.Int, reflect.Int64:
				f.SetInt(int64(100 + i))
			case reflect.Float64:
				f.SetFloat(1.25 + float64(i))
			case reflect.Struct:
				if f.Type() == reflect.TypeOf(time.Time{}) {
					f.Set(reflect.ValueOf(time.Date(2026, 10, 9, 1, 2, 3, 4, time.UTC)))
					continue
				}
				t.Fatalf("%s: unhandled struct field; extend this test", name)
			default:
				t.Fatalf("%s: unhandled kind %s; extend this test", name, f.Kind())
			}
		}
	}

	b, err := json.Marshal(toCacheLogEntry(in))
	if err != nil {
		t.Fatal(err)
	}
	var e cache.LogEntry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	out := reflect.ValueOf(fromCacheLogEntry(e))
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if name == "WAFEngineBlocking" {
			continue
		}
		a, b := v.Field(i).Interface(), out.Field(i).Interface()
		if ta, ok := a.(time.Time); ok {
			if !ta.Equal(b.(time.Time)) {
				t.Errorf("%s lost in the Valkey buffer: %v -> %v", name, a, b)
			}
			continue
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s lost in the Valkey buffer: %v -> %v", name, a, b)
		}
	}
}
