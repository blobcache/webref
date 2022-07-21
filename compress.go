package webref

import (
	"compress/gzip"
	"io"
)

type Decompressor = func(x io.ReadCloser) (io.ReadCloser, error)

func GZIPDecompress(x io.ReadCloser) (io.ReadCloser, error) {
	return gzip.NewReader(x)
}
