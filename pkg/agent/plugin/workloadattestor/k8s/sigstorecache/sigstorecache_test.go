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
			if got := NewCache(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCacheimpl_GetSignature(t *testing.T) {
	type fields struct {
		size  int
		items *list.List
	}
	type args struct {
		key string
	}
	item1 := Item{
		Key: "key1",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
					"critical": {
						"identity": {
							"docker-reference": "docker-registry.com/some/image"},
							"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},
							"type": "some type"
						},
						"optional": {
							"subject": "spirex@example.com"
							}
						}`),
			},
		},
	}
	cacheMemory := NewCache().(*Cacheimpl)
	cacheMemory.PutSignature(item1)

	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Item
	}{
		{
			name: "key1",
			fields: fields{
				size:  1,
				items: cacheMemory.items,
			},
			args: args{
				key: "key1",
			},
			want: cacheMemory.GetSignature(item1.Key),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Cacheimpl{
				size:  tt.fields.size,
				items: tt.fields.items,
			}
			got := c.GetSignature(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Cacheimpl.GetSignature() = %v, want %v", got.Key, tt.want.Key)
			}
		})
	}
}

func TestCacheimpl_PutSignature(t *testing.T) {
	type fields struct {
		size  int
		items *list.List
	}
	type args struct {
		i Item
	}
	item1 := Item{
		Key: "key1",
		Value: []oci.Signature{
			signature{
				payload: []byte(`{
					"critical": {
						"identity": {
							"docker-reference": "docker-registry.com/some/image"},
							"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},
							"type": "some type"
						},
						"optional": {
							"subject": "spirex@example.com"
							}
						}`),
			},
		},
	}
	cacheMemory := NewCache().(*Cacheimpl)
	cacheMemory.PutSignature(item1)
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "key1",
			fields: fields{
				size:  1,
				items: cacheMemory.items,
			},
			args: args{
				i: Item{Key: "key"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cacheimpl{
				size:  tt.fields.size,
				items: tt.fields.items,
			}
			c.PutSignature(tt.args.i)
		})
	}
}
