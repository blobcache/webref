package webref

import (
	"errors"
	"fmt"
)

type Ref []Stage

func (r Ref) Validate() error {
	if len(r) == 0 {
		return errors.New("zero-length ref")
	}
	if !r[0].IsSource() {
		return errors.New("first ref element is not a Source")
	}
	if len(r) > 1 {
		for i, s := range r[1:] {
			if s.IsSource() {
				return fmt.Errorf("webref: source found at index > 0: %d", i+1)
			}
		}
	}
	return nil
}

func (r Ref) IsMutable() bool {
	for i := len(r); i >= 0; i-- {
		s := r[i]
		switch {
		case s.File != nil:
			return true
		case s.HTTP != nil:
			return true
		case s.IPFS != nil:
			return false

		case s.Cipher != nil:
		case s.Slice != nil:
		case s.Hash != nil:
			return false

		case s.Any != nil:
			return true
		case s.Table != nil:
			// If any of the regions in the table are mutable, then the table is mutable.
			for _, te := range s.Table {
				if te.Target.IsMutable() {
					return true
				}
			}
			return false
		default:
			panic(s)
		}
	}
	return false
}

type Stage struct {
	File *FileSource `json:"file,omitempty"`
	HTTP *HTTPSource `json:"http,omitempty"`
	IPFS *IPFSSource `json:"ipfs,omitempty"`

	Cipher   *CipherStage   `json:"cipher,omitempty"`
	AEAD     *AEADStage     `json:"aead,omitempty`
	Compress *CompressStage `json:"compress,omitempty`
	Slice    *SliceStage    `json:"slice,omitempty"`

	Hash *HashCheck `json:"hash,omitempty"`

	Any   AnySource   `json:"any,omitempty"`
	Table TableSource `json:"table,omitempty"`
}

func (s Stage) IsSource() bool {
	switch {
	case s.File != nil:
		return true
	case s.HTTP != nil:
		return true
	case s.IPFS != nil:
		return true

	case s.Any != nil:
		return true
	case s.Table != nil:
		return true
	default:
		return false
	}
}

func (s Stage) String() string {
	switch {
	case s.File != nil:
		return fmt.Sprintf("File(%s)", *s.File)
	case s.HTTP != nil:
		return fmt.Sprintf("HTTP{url=%s, headers=%v}", s.HTTP.URL, s.HTTP.Headers)

	case s.Hash != nil:
		return fmt.Sprintf("Hash{algo=%v sum=%x}", s.Hash.Algo, s.Hash.Sum)
	case s.Cipher != nil:
		return fmt.Sprintf("Cipher{algo=%v}", s.Cipher.Algo)
	case s.Compress != nil:
		return fmt.Sprintf("Compress{algo=%v}", s.Compress.Algo)
	default:
		return "EMPTY"
	}
}

type FileSource string

type HTTPSource struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type IPFSSource string

type CipherAlgo string

const (
	Cipher_AES256_CTR = "AES256_CTR"
	Cipher_CHACHA20   = "CHACHA20"
	Cipher_XCHACHAX20 = "XCHACHA20"
)

type CipherStage struct {
	Algo  CipherAlgo `json:"algo"`
	Key   []byte     `json:"key"`
	Nonce []byte     `json:"nonce"`
}

type AEADAlgo string

const (
	AEAD_AES256_GCM      = "AES256_GCM"
	AEAD_XCHACHAPOLY1305 = "XCHACHAPOLY1305"
)

type AEADStage struct {
	Algo  AEADAlgo `json:"algo"`
	Key   []byte   `json:"key"`
	Nonce []byte   `json:"nonce"`
}

type SliceStage struct {
	Begin int `json:"begin"`
	End   int `json:"end"`
}

type CompressAlgo string

const (
	GZIP   = "gzip"
	SNAPPY = "snap"
)

type CompressStage struct {
	Algo CompressAlgo `json:"algo"`
}

type HashAlgo string

const (
	Hash_SHA256 = "SHA256"

	Hash_SHA3_256 = "SHA3_256"

	Hash_BLAKE2B = "BLAKE2B"
	Hash_BLAKE2S = "BLAKE2S"
	Hash_BLAKE3  = "BLAKE3"
)

type HashCheck struct {
	Algo HashAlgo `json:"algo"`
	Sum  []byte   `json:"sum"`
}

type AnySource []Ref

type TableSource []TableEntry

type TableEntry struct {
	Offset uint64
	Target Ref
}
