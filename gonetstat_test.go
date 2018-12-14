package GOnetstat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTcp(t *testing.T) {
	p, err := Tcp()
	assert.Nil(t, err)

	for i, v := range p {
		t.Logf("%d -> %#v", i, v)
	}
}

func BenchmarkTcp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Tcp()
	}
}

func BenchmarkAll(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Udp()
		Tcp()
		Tcp6()
		Udp6()
	}
}
