package webref

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"

	"golang.org/x/crypto/blake2b"
	"lukechampine.com/blake3"
)

type Option func(*Resolver)

func WithOpenFile(fn func(string) (io.ReadSeekCloser, error)) Option {
	return func(r *Resolver) {
		r.openFile = fn
	}
}

func WithHTTPClient(hc *http.Client) Option {
	return func(r *Resolver) {
		r.hc = hc
	}
}

func WithHash(algo HashAlgo, fn func() hash.Hash) Option {
	return func(r *Resolver) {
		r.hashers[algo] = fn
	}
}

func WithCipher(algo CipherAlgo, fn Decryptor) Option {
	return func(r *Resolver) {
		r.decryptors[algo] = fn
	}
}

func WithCompression(algo CompressAlgo, fn Decompressor) Option {
	return func(r *Resolver) {
		r.decompressors[algo] = fn
	}
}

type Resolver struct {
	hc       *http.Client
	openFile func(string) (io.ReadSeekCloser, error)

	hashers       map[HashAlgo]func() hash.Hash
	decryptors    map[CipherAlgo]Decryptor
	aeads         map[AEADAlgo]func([]byte) (cipher.AEAD, error)
	decompressors map[CompressAlgo]Decompressor
}

func NewResolver(opts ...Option) Resolver {
	r := Resolver{
		hc: http.DefaultClient,
		openFile: func(string) (io.ReadSeekCloser, error) {
			return nil, errors.New("webref: resolver does not have file opener configured")
		},
		decryptors: map[CipherAlgo]Decryptor{
			Cipher_CHACHA20:   ChaCha20Decrypt,
			Cipher_XCHACHAX20: ChaCha20Decrypt,
			Cipher_AES256_CTR: AES256CTRDecrypt,
		},
		hashers: map[HashAlgo]func() hash.Hash{
			Hash_SHA256: sha256.New,
			Hash_BLAKE2B: func() hash.Hash {
				h, err := blake2b.New256(nil)
				if err != nil {
					panic(err)
				}
				return h
			},
			Hash_BLAKE3: func() hash.Hash { return blake3.New(32, nil) },
		},
		aeads:         map[AEADAlgo]func([]byte) (cipher.AEAD, error){},
		decompressors: map[CompressAlgo]Decompressor{},
	}
	return r
}

func (r *Resolver) Resolve(ctx context.Context, x Ref) (io.ReadCloser, error) {
	if len(x) == 0 {
		return nil, errors.New("empty ref")
	}
	var rc io.ReadCloser
	setSource := func(rc2 io.ReadCloser) error {
		if rc != nil {
			rc.Close()
			return errors.New("source found after first stage")
		}
		rc = rc2
		return nil
	}
	for _, s := range x {
		switch {
		case s.File != nil:
			rc2, err := r.openFile(string(*s.File))
			if err != nil {
				return nil, err
			}
			if err := setSource(rc2); err != nil {
				return nil, err
			}
		case s.HTTP != nil:
			res, err := r.hc.Get(s.HTTP.URL)
			if err != nil {
				return nil, err
			}
			if err := setSource(res.Body); err != nil {
				return nil, err
			}
		case s.IPFS != nil:
			panic(s.IPFS)

		case s.Cipher != nil:
			rc2, err := r.resolveCipher(rc, *s.Cipher)
			if err != nil {
				return nil, err
			}
			rc = rc2
		case s.AEAD != nil:
			rc2, err := r.resolveAEAD(rc, *s.AEAD)
			if err != nil {
				return nil, err
			}
			rc = rc2
		case s.Hash != nil:
			rc2, err := r.resolveHash(rc, *s.Hash)
			if err != nil {
				return nil, err
			}
			rc = rc2
		case s.Compress != nil:
			rc2, err := r.resolveCompress(rc, *s.Compress)
			if err != nil {
				return nil, err
			}
			rc = rc2
		case s.Slice != nil:
			rc2, err := r.resolveSlice(rc, *s.Slice)
			if err != nil {
				return nil, err
			}
			rc = rc2
		case s.Any != nil:
			panic(s.Any)
		case s.Table != nil:
			panic(s.Table)
		default:
			return nil, ErrEmptyStage{}
		}
	}
	return rc, nil
}

func (r *Resolver) resolveCipher(x io.ReadCloser, c CipherStage) (io.ReadCloser, error) {
	dec, exists := r.decryptors[c.Algo]
	if !exists {
		return nil, ErrAlgoUnsupported{Algo: string(c.Algo), Type: "cipher"}
	}
	return dec(x, c.Key, c.Nonce)
}

func (r *Resolver) resolveAEAD(x io.ReadCloser, c AEADStage) (io.ReadCloser, error) {
	newAEAD, exists := r.aeads[c.Algo]
	if !exists {
		return nil, ErrAlgoUnsupported{Type: "AEAD", Algo: string(c.Algo)}
	}
	a, err := newAEAD(c.Key)
	if err != nil {
		return nil, err
	}
	data, err := r.readAll(x)
	if err != nil {
		return nil, err
	}
	data, err = a.Open(data, c.Nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (r *Resolver) resolveHash(x io.ReadCloser, c HashCheck) (io.ReadCloser, error) {
	newHash, exists := r.hashers[c.Algo]
	if !exists {
		return nil, ErrAlgoUnsupported{Type: "hash", Algo: string(c.Algo)}
	}
	data, err := r.readAll(x)
	if err != nil {
		return nil, err
	}
	h := newHash()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (r *Resolver) resolveSlice(x io.ReadCloser, c SliceStage) (io.ReadCloser, error) {
	if c.End < c.Begin {
		return nil, fmt.Errorf("webref: slice end < begin. %d < %d", c.End, c.Begin)
	}
	if rsc, ok := x.(io.ReadSeekCloser); ok {
		_, err := rsc.Seek(int64(c.Begin), io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		return closer{
			Reader: io.LimitReader(rsc, int64(c.End-c.Begin)),
			close:  rsc.Close,
		}, nil
	}
	data, err := r.readAll(x)
	if err != nil {
		return nil, err
	}
	if len(data) < c.End {
		return nil, errors.New("webref: slice is out of bounds")
	}
	return io.NopCloser(bytes.NewReader(data[c.Begin:c.End])), nil
}

func (r *Resolver) resolveCompress(x io.ReadCloser, cs CompressStage) (io.ReadCloser, error) {
	dec, exists := r.decompressors[cs.Algo]
	if !exists {
		return nil, ErrAlgoUnsupported{Type: "hash", Algo: string(cs.Algo)}
	}
	return dec(x)
}

func (r *Resolver) resolveAny(ctx context.Context, x AnySource) (io.ReadCloser, error) {
	if len(x) == 0 {
		return nil, errors.New("empty any")
	}
	var retErr error
	n := rand.Intn(len(x))
	for i := 0; i < len(x); i++ {
		ref := x[(i+n)%len(x)]
		rc, err := r.Resolve(ctx, ref)
		if err != nil {
			retErr = err
		} else {
			return rc, nil
		}
	}
	return nil, retErr
}

func (r *Resolver) readAll(x io.ReadCloser) ([]byte, error) {
	// TODO: per stage limit
	data, err := ioutil.ReadAll(x)
	if err != nil {
		return nil, err
	}
	if err := x.Close(); err != nil {
		return nil, err
	}
	return data, nil
}

type closer struct {
	io.Reader
	close func() error
}

func (c closer) Close() error {
	return c.close()
}
