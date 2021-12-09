package sigstore

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/stretchr/testify/assert"
)

func TestExtractSelectorOfSignedImage(t *testing.T) {
	sigstore := New()

	for _, tc := range []struct {
		name     string
		payload  []cosign.SignedPayload
		expected string
	}{
		{
			name: "with one payload",
			payload: []cosign.SignedPayload{
				{
					Payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			expected: "spirex@hpe.com",
		},
		{
			name: "with two payloads",
			payload: []cosign.SignedPayload{
				{
					Payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "hpe@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
				{
					Payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			expected: "hpe@hpe.com",
		},
		{
			name: "with no invalid payload",
			payload: []cosign.SignedPayload{
				{
					Payload: []byte{},
				},
			},
			expected: "",
		},
		{
			name: "with subject certificate",
			payload: []cosign.SignedPayload{
				{
					Payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
					Cert: &x509.Certificate{
						EmailAddresses: []string{
							"spirex@hpe.com",
							"hpe@hpe.com",
						},
					},
				},
			},
			expected: "spirex@hpe.com",
		},
		{
			name: "with URI certificate",
			payload: []cosign.SignedPayload{
				{
					Payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
					Cert: &x509.Certificate{
						URIs: []*url.URL{
							{
								Scheme: "https",
								Host:   "www.hpe.com",
								Path:   "somepath1",
							},
							{
								Scheme: "https",
								Host:   "www.spirex.com",
								Path:   "somepath2",
							},
						},
					},
				},
			},
			expected: "https://www.hpe.com/somepath1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("payload: %s", string(tc.payload[0].Payload))

			assert.Equal(t, tc.expected, sigstore.ExtractselectorOfSignedImage(tc.payload))
		})
	}
}
