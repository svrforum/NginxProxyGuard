package util

import (
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
)

// ParseIntParam extracts and validates an integer query parameter
// Returns defaultVal if parsing fails or value is out of range
func ParseIntParam(c echo.Context, name string, defaultVal, minVal, maxVal int) int {
	str := c.QueryParam(name)
	if str == "" {
		return defaultVal
	}

	val, err := strconv.Atoi(str)
	if err != nil {
		return defaultVal
	}

	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}

	return val
}

// ParseLimitParam parses a limit parameter with config defaults
func ParseLimitParam(c echo.Context, defaultLimit int) int {
	return ParseIntParam(c, "limit", defaultLimit, 1, config.MaxPageSize)
}

// ParseOffsetParam parses an offset parameter
func ParseOffsetParam(c echo.Context) int {
	return ParseIntParam(c, "offset", 0, 0, 10000)
}

// ParsePageParam parses a page parameter (1-based)
func ParsePageParam(c echo.Context) int {
	return ParseIntParam(c, "page", 1, 1, 10000)
}

// ParseTimeParam parses a time parameter in RFC3339 format
// Returns nil if parsing fails or parameter is empty
func ParseTimeParam(c echo.Context, name string) *time.Time {
	str := c.QueryParam(name)
	if str == "" {
		return nil
	}

	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil
	}

	return &t
}

// ParseTimeRange parses start_time and end_time parameters
// Returns the parsed times or nil for each if parsing fails
func ParseTimeRange(c echo.Context) (start *time.Time, end *time.Time) {
	return ParseTimeParam(c, "start_time"), ParseTimeParam(c, "end_time")
}

// ParseBoolParam parses a boolean query parameter
// Returns defaultVal if parameter is empty or invalid
func ParseBoolParam(c echo.Context, name string, defaultVal bool) bool {
	str := c.QueryParam(name)
	if str == "" {
		return defaultVal
	}

	val, err := strconv.ParseBool(str)
	if err != nil {
		return defaultVal
	}

	return val
}

// ParseStringArrayParam parses a comma-separated string array
// Returns nil if parameter is empty, limits array size to maxSize
func ParseStringArrayParam(c echo.Context, name string, maxSize int) []string {
	str := c.QueryParam(name)
	if str == "" {
		return nil
	}

	// Simple split - caller can do more sophisticated parsing if needed
	var result []string
	start := 0
	for i := 0; i <= len(str); i++ {
		if i == len(str) || str[i] == ',' {
			if i > start {
				item := str[start:i]
				result = append(result, item)
				if len(result) >= maxSize {
					break
				}
			}
			start = i + 1
		}
	}

	return result
}

// ParseStatusCodeParam parses a status_code parameter
// Returns nil if parsing fails or parameter is empty
func ParseStatusCodeParam(c echo.Context) *int {
	str := c.QueryParam("status_code")
	if str == "" {
		return nil
	}

	code, err := strconv.Atoi(str)
	if err != nil {
		return nil
	}

	// Validate HTTP status code range
	if code < 100 || code > 599 {
		return nil
	}

	return &code
}
