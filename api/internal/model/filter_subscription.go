package model

import "time"

type FilterSubscription struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	URL           string     `json:"url"`
	Format        string     `json:"format"`
	Type          string     `json:"type"`
	Enabled       bool       `json:"enabled"`
	RefreshType   string     `json:"refresh_type"`
	RefreshValue  string     `json:"refresh_value"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"`
	EntryCount        int        `json:"entry_count"`
	ExcludePrivateIPs bool       `json:"exclude_private_ips"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type FilterSubscriptionEntry struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	Value          string    `json:"value"`
	Reason         string    `json:"reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type FilterSubscriptionHostExclusion struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	ProxyHostID    string    `json:"proxy_host_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type FilterSubscriptionEntryExclusion struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	Value          string    `json:"value"`
	CreatedAt      time.Time `json:"created_at"`
}

type AddEntryExclusionRequest struct {
	Value string `json:"value"`
}

type CreateFilterSubscriptionRequest struct {
	URL          string `json:"url"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	RefreshType  string `json:"refresh_type,omitempty"`
	RefreshValue string `json:"refresh_value,omitempty"`
}

type UpdateFilterSubscriptionRequest struct {
	Name         *string `json:"name,omitempty"`
	Enabled      *bool   `json:"enabled,omitempty"`
	RefreshType  *string `json:"refresh_type,omitempty"`
	RefreshValue      *string `json:"refresh_value,omitempty"`
	ExcludePrivateIPs *bool   `json:"exclude_private_ips,omitempty"`
}

type CatalogSubscribeRequest struct {
	Paths        []string `json:"paths"`
	RefreshType  string   `json:"refresh_type,omitempty"`
	RefreshValue string   `json:"refresh_value,omitempty"`
}

type FilterSubscriptionListResponse struct {
	Data       []FilterSubscription `json:"data"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"per_page"`
	TotalPages int                  `json:"total_pages"`
}

type FilterSubscriptionDetail struct {
	FilterSubscription
	Entries         []FilterSubscriptionEntry          `json:"entries"`
	Exclusions      []FilterSubscriptionHostExclusion  `json:"exclusions"`
	EntryExclusions []FilterSubscriptionEntryExclusion `json:"entry_exclusions"`
}

type FilterCatalog struct {
	Version     int                  `json:"version"`
	GeneratedAt string               `json:"generated_at"`
	Lists       []FilterCatalogEntry `json:"lists"`
}

type FilterCatalogEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Path        string `json:"path"`
	EntryCount  int    `json:"entry_count"`
	UpdatedAt   string `json:"updated_at"`
	Subscribed  bool   `json:"subscribed,omitempty"`
}

type NPGFilterList struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Type        string           `json:"type"`
	Expires     string           `json:"expires"`
	MaxEntries  int              `json:"max_entries,omitempty"`
	Entries     []NPGFilterEntry `json:"entries"`
}

type NPGFilterEntry struct {
	Value       string `json:"value"`
	Reason      string `json:"reason"`
	Added       string `json:"added"`
	Contributor string `json:"contributor"`
}
