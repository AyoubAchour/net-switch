package testsupport

import (
	"reflect"
	"testing"
)

func TestOrderedPolicyComparison(t *testing.T) {
	for _, key := range []string{"appLines", "shares"} {
		if reflect.DeepEqual(ordered([]byte(`{"b":1,"a":2}`), key), ordered([]byte(`{"a":2,"b":1}`), key)) {
			t.Fatal(key)
		}
	}
	if !reflect.DeepEqual(ordered([]byte(`{"b":1,"a":2}`), ""), ordered([]byte(`{"a":2,"b":1}`), "")) {
		t.Fatal("ordinary object order is insignificant")
	}
}
