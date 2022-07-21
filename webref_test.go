package webref

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	x := Ref{
		Stage{
			HTTP: &HTTPSource{
				URL: "https://example.com/1234",
			},
		},
		Stage{
			Hash: &HashCheck{
				Algo: Hash_BLAKE2B,
				Sum:  make([]byte, 32),
			},
		},
	}
	data := EncodePEM(nil, x)
	t.Log(string(data))

	y, err := DecodePEM(data)
	require.NoError(t, err)
	t.Log(y)
	require.Equal(t, &x, y)
}
