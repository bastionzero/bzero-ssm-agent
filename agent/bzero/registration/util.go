package registration

const (
	BZeroConfigStorage = "BZeroConfig"
	BZeroRegStorage    = "BZeroRegistration"
)

// Struct to allow for backwards/forwards compatability in registration flow dumb
type BZeroRegInfo struct {
	RegID      string `json:"registrationId"`
	RegSecret  string `json:"registrationSecret"`
	TargetName string `json:"instanceName"`
	EnvID      string `json:"environmentId"`
	APIUrl     string `json:"apiUrl"`
}
