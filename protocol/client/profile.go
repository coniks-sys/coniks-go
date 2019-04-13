package client

// Profile is the user ID and whatever can be serialize to byte array go here
type Profile struct {
	UserID      string
	ProfileData []byte
}

// NewProfile encodes the profile data to a byte array
// and returns the profile of the given user.
func NewProfile(userID string, key []byte) *Profile {
	return &Profile{
		UserID:      userID,
		ProfileData: key,
	}
}
