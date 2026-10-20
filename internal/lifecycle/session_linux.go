package lifecycle

// Linux does not hibernate services across a shutdown and uses a new boot ID.
// Desktop connection closure alone must never be treated as an OS sign-out.
func ownerSessionPresent(string, uint32) (bool, error) { return true, nil }
