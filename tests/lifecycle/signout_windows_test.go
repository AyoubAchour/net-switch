package lifecycle_test

import "testing"

func ownerSignout(t *testing.T, _ *client, _ actor) {
	t.Skip("real logind case; Windows has SCM event and WTS cases")
}
func cliActivation(t *testing.T, _ actor) { t.Skip("Linux socket activation regression") }
