package pack

// Config holds runtime or private local settings. No deployment values or
// signed executable trailers are compiled into the generic client.
type Config struct {
	Server   string `json:"server"`
	CA       string `json:"ca,omitempty"`
	BatchID  string `json:"batch_id"`
	Token    string `json:"token"`
	Group    string `json:"group"`
	AutoUser string `json:"auto_user,omitempty"`
	Protocol int    `json:"protocol"`
}
