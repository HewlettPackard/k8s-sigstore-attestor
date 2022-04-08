package sigstorecache

import (
	"container/list"
	"crypto/x509"
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/pkg/oci"
)

type signature struct {
	v1.Layer

	payload []byte
	cert    *x509.Certificate
	bundle  *oci.Bundle
}

func (signature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s signature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (signature) Base64Signature() (string, error) {
	return "", nil
}

func (s signature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (signature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (s signature) Bundle() (*oci.Bundle, error) {
	return s.bundle, nil
}

func TestNewCache(t *testing.T) {
	tests := []struct {
		name string
		want Cache
	}{
		{
			name: "New",
			want: &Cacheimpl{
				size:  3,
				items: list.New(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewCache(3); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCacheimpl_GetSignature(t *testing.T) {
	cacheInstance := NewCache(3).(*Cacheimpl)

	item1 := Item{
		Key: "signature1",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
					"critical": {
						"identity": {
							"docker-reference": "docker-registry.com/some/image"},
							"image": {"docker-manifest-digest": "11111111111111"},
							"type": "some type"
						},
						"optional": {
							"subject": "spirex1@example.com"
							}
						},
					}`),
			},
		},
	}

	item2 := Item{
		Key: "signature2",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
					"critical": {
						"identity": {
							"docker-reference": "docker-registry.com/some/image"},
							"image": {"docker-manifest-digest2": "2222222222222"},
							"type": "some type"
						},
						"optional": {
							"subject": "spirex2@example.com"
							},
						},
					},`),
			},
		},
	}

	item3 := Item{
		Key: "signature3",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
								"critical": {
									"identity": {
										"docker-reference": "docker-registry.com/some/image"
									},
									"image": {
										"docker-manifest-digest3": "3333333333333"
									},
									"type": "some type"
								}
								"optional": {
									"subject": "spirex3@example.com"
								}
							}`),
			},
		},
	}

	cacheInstance.PutSignature(item1)
	cacheInstance.PutSignature(item2)

	item4 := cacheInstance.GetSignature(item3.Key)
	if item4 != nil {
		t.Error("a non-existing item's key should return a nil item")
	}

	item5 := cacheInstance.GetSignature(item1.Key)
	if !reflect.DeepEqual(item5.Value, item1.Value) {
		t.Error("an existing items key's should return the existing item")
	}
}

func TestCacheimpl_PutSignature(t *testing.T) {
	cacheInstance := NewCache(2).(*Cacheimpl)

	item1 := Item{
		Key: "signature1",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
					"critical": {
						"identity": {
							"docker-reference": "docker-registry.com/some/image"},
							"image": {"docker-manifest-digest": "11111111111111"},
							"type": "some type"
						},
						"optional": {
							"subject": "spirex1@example.com"
							}
						},
					}`),
			},
		},
	}

	item2 := Item{
		Key: "signature2",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
					"critical": {
						"identity": {
							"docker-reference": "docker-registry.com/some/image"},
							"image": {"docker-manifest-digest2": "2222222222222"},
							"type": "some type"
						},
						"optional": {
							"subject": "spirex2@example.com"
							},
						},
					},`),
			},
		},
	}

	item3 := Item{
		Key: "signature3",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
								"critical": {
									"identity": {
										"docker-reference": "docker-registry.com/some/image"
									},
									"image": {
										"docker-manifest-digest3": "3333333333333"
									},
									"type": "some type"
								}
								"optional": {
									"subject": "spirex3@example.com"
								}
							}`),
			},
		},
	}

	item4 := Item{
		Key: "signature3",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
								"critical": {
									"identity": {
										"docker-reference": "docker-registry.com/some/image"
									},
									"image": {
										"docker-manifest-digest4": "4444444444444"
									},
									"type": "some type"
								}
								"optional": {
									"subject": "spirex4@example.com"
								}
							}`),
			},
		},
	}
	cacheInstance.PutSignature(item1)
	cacheInstance.PutSignature(item2)

	if cacheInstance.items.Len() != 2 {
		t.Error("item count should be 2 after putting 2 keys", cacheInstance.items.Len())
	}

	cacheInstance.PutSignature(item1)
	if cacheInstance.items.Len() != 2 {
		t.Error("item count should stay the same after putting an existing key", cacheInstance.items.Len())
	}

	cacheInstance.PutSignature(item3)
	if cacheInstance.items.Len() != 2 {
		t.Error("item count should stay the same after putting a new key that overflows the cache", cacheInstance.items.Len())
	}

	cacheInstance.PutSignature(item4)
	wantcached := cacheInstance.GetSignature(item4.Key)
	if !reflect.DeepEqual(wantcached.Value, item4.Value) {
		t.Error("an existing items key's should return the existing item")
	}
}
