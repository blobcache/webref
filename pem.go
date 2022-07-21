package webref

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// EncodePEM appends the canonical PEM encoding of the Ref x to out.
func EncodePEM(out []byte, x Ref) []byte {
	data, err := json.Marshal(x)
	if err != nil {
		panic(err)
	}
	buf := bytes.Buffer{}
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err := gw.Write(data); err != nil {
		panic(err)
	}
	if err := gw.Close(); err != nil {
		panic(err)
	}
	data = buf.Bytes()
	return append(out, pem.EncodeToMemory(&pem.Block{
		Type:  "WEBREF",
		Bytes: data,
	})...)
}

// DecodePEM decodes a Ref from it's canonical PEM encoding in x.
func DecodePEM(x []byte) (*Ref, error) {
	block, _ := pem.Decode(x)
	if block.Type != "WEBREF" {
		return nil, fmt.Errorf("webref: decoding pem, wrong type %q", block.Type)
	}
	gr, err := gzip.NewReader(bytes.NewReader(block.Bytes))
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(gr)
	if err != nil {
		return nil, err
	}
	var r Ref
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}
