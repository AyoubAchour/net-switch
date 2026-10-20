package lifecycle_test

import "testing"

func ownerSignout(t *testing.T, _ *client, _ actor) {
	t.Skip("real logind case; Windows has SCM event and WTS cases")
}
