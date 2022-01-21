package sigstore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	corev1 "k8s.io/api/core/v1"
)

type signature struct {
	v1.Layer

	payload []byte
	cert    *x509.Certificate
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

func (signature) Bundle() (*oci.Bundle, error) {
	return nil, nil
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		want Sigstore
	}{
		{
			name: "New",
			want: &Sigstoreimpl{verifyFunction: cosign.VerifyImageSignatures, validateImageRefFunction: ValidateImage},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(); fmt.Sprintf("%v", got) != fmt.Sprintf("%v", tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_FetchImageSignatures(t *testing.T) {
	type fields struct {
		verifyFunction           func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		validateImageRefFunction func(name.Reference) (bool, error)
	}
	type args struct {
		imageName string
		rekorURL  string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []oci.Signature
		wantErr bool
	}{
		{
			name: "fetch image with signature",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			wantErr: false,
		},
		{
			name: "fetch image with 2 signatures",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 4","key3": "value 5"}}`),
						},
					}, true, nil
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 4","key3": "value 5"}}`),
				},
			},
			wantErr: false,
		},
		{
			name: "fetch image with invalid rekor url",
			fields: fields{
				verifyFunction: nil,
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "path-no-host", // URI parser uses this as path, not host
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid rekor host",
			fields: fields{
				verifyFunction: nil,
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "http://invalid.{{}))}.url.com", // invalid url
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid rekor scheme",
			fields: fields{
				verifyFunction: nil,
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "abc://invalid.url.com", // invalid scheme
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with no signature",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{}, true, fmt.Errorf("no matching signatures 1")
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{ // TODO: check again, same as above test. should never happen, since the verify function returns an error on empty verified signature list
			name: "fetch image with no signature and no error",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{}, true, fmt.Errorf("no matching signatures 2")
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature and error",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, errors.New("some error")
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature no error, bundle not verified",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					}}, false, nil
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid image reference",
			fields: fields{
				verifyFunction:           nil,
				validateImageRefFunction: nil,
			},
			args: args{
				imageName: "invali|].url.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature, empty rekor url",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			wantErr: false,
		},
		{
			name: "fetch image with invalid image ref",
			fields: fields{
				verifyFunction: nil,
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return false, errors.New("invalid image ref")
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := Sigstoreimpl{
				verifyFunction:           tt.fields.verifyFunction,
				validateImageRefFunction: tt.fields.validateImageRefFunction,
			}
			got, err := sigstore.FetchImageSignatures(tt.args.imageName, tt.args.rekorURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.FetchImageSignatures() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.FetchImageSignatures() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_ExtractSelectorsFromSignatures(t *testing.T) {
	type fields struct {
		verifyFunction func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}
	type args struct {
		signatures []oci.Signature
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []string
	}{
		{
			name: "extract selector from single image signature array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: []string{"image-signature-subject:spirex@hpe.com"},
		},
		{
			name: "extract selector from image signature array with multiple entries",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex1@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex2@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: []string{"image-signature-subject:spirex1@hpe.com", "image-signature-subject:spirex2@hpe.com"},
		},
		{
			name: "with invalid payload",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte{},
					},
				},
			},
			want: nil,
		},
		{
			name: "extract selector from image signature with subject certificate",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
						cert: &x509.Certificate{
							EmailAddresses: []string{
								"spirex@hpe.com",
								"hpe@hpe.com",
							},
						},
					},
				},
			},
			want: []string{"image-signature-subject:spirex@hpe.com"},
		},
		{
			name: "extract selector from image signature with URI certificate",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
						cert: &x509.Certificate{
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
			},
			want: []string{"image-signature-subject:https://www.hpe.com/somepath1"},
		},
		{
			name: "extract selector from empty array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{},
			},
			want: nil,
		},
		{
			name: "extract selector from nil array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: nil,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Sigstoreimpl{
				verifyFunction: tt.fields.verifyFunction,
			}
			if got := s.ExtractSelectorsFromSignatures(tt.args.signatures); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.ExtractSelectorsFromSignatures() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func Test_getOnlySubject(t *testing.T) {
// 	type args struct {
// 		payload string
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want string
// 	}{
// 		// TODO: Add test cases.
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "test1",
// 			},
// 			want: "",
// 		},
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "test2\n",
// 			},
// 			want: "",
// 		},
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "[{\"optional\":{\"Subject\":\"test3\"}}]",
// 			},
// 			want: "test3",
// 		},
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "[{\"optional\":{\"Subject\":\"test4\"}},{\"optional\":{\"Subject\":\"test5\"}}]",
// 			},
// 			want: "test4",
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := getOnlySubject(tt.args.payload); got != tt.want {
// 				t.Errorf("getOnlySubject() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

type noCertSignature signature

func (noCertSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s noCertSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (noCertSignature) Base64Signature() (string, error) {
	return "", nil
}

func (noCertSignature) Cert() (*x509.Certificate, error) {
	return nil, errors.New("no cert test")
}

func (noCertSignature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (noCertSignature) Bundle() (*oci.Bundle, error) {
	return nil, nil
}

type noPayloadSignature signature

func (noPayloadSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (noPayloadSignature) Payload() ([]byte, error) {
	return nil, errors.New("no payload test")
}

func (noPayloadSignature) Base64Signature() (string, error) {
	return "", nil
}

func (s noPayloadSignature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (noPayloadSignature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (noPayloadSignature) Bundle() (*oci.Bundle, error) {
	return nil, nil
}

func Test_certSubject(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "certSubject_single_email",
			args: args{
				c: &x509.Certificate{
					EmailAddresses: []string{"example@example.com"},
				},
			},
			want: "example@example.com",
		},
		{
			name: "certSubject_multiple_email",
			args: args{
				c: &x509.Certificate{
					EmailAddresses: []string{"example1@example1.com", "example2@example1.com"},
				},
			},
			want: "example1@example1.com",
		},
		{
			name: "certSubject_from_single_URI",
			args: args{
				c: &x509.Certificate{
					URIs: []*url.URL{
						{
							User: url.User("example"), Host: "example2.com"},
					},
				},
			},
			want: "example@example2.com",
		},
		{
			name: "certSubject_from_multiple_URIs",
			args: args{
				c: &x509.Certificate{
					URIs: []*url.URL{
						{
							User: url.User("example1"),
							Host: "example2.com",
						},
						{
							User: url.User("example2"),
							Host: "example2.com",
						},
					},
				},
			},
			want: "example1@example2.com",
		},
		{
			name: "certSubject_empty_certificate",
			args: args{
				c: &x509.Certificate{},
			},
			want: "",
		},
		{
			name: "certSubject_nil_certificate",
			args: args{
				c: nil,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certSubject(tt.args.c); got != tt.want {
				t.Errorf("certSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_SkipImage(t *testing.T) {
	type fields struct {
		verifyFunction           func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		skippedImages            map[string]([]string)
		validateImageRefFunction func(ref name.Reference) (bool, error)
	}
	type args struct {
		status corev1.ContainerStatus
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "skipping only image in list",
			fields: fields{
				verifyFunction: nil,
				skippedImages: map[string][]string{
					"sha256:sampleimagehash": {
						"image-signature-subject:sampleimage",
					},
				},
				validateImageRefFunction: func(ref name.Reference) (bool, error) {
					return true, nil
				},
			},
			args: args{
				status: corev1.ContainerStatus{
					ImageID: "sha256:sampleimagehash",
				},
			},
			want:    []string{"image-signature-subject:sampleimage"},
			wantErr: false,
		},
		{
			name: "skipping image in list",
			fields: fields{
				verifyFunction: nil,
				skippedImages: map[string][]string{
					"sha256:sampleimagehash": {
						"image-signature-subject:sampleimage",
					},
					"sha256:sampleimagehash2": {
						"image-signature-subject:sampleimage2",
					},
					"sha256:sampleimagehash3": {
						"image-signature-subject:sampleimage3",
					},
				},
			},
			args: args{
				status: corev1.ContainerStatus{
					ImageID: "sha256:sampleimagehash2",
				},
			},
			want:    []string{"image-signature-subject:sampleimage2"},
			wantErr: false,
		},
		{
			name: "image not in list",
			fields: fields{
				verifyFunction: nil,
				skippedImages: map[string][]string{
					"sha256:sampleimagehash": {
						"image-signature-subject:sampleimage",
					},
					"sha256:sampleimagehash3": {
						"image-signature-subject:sampleimage3",
					},
				},
			},
			args: args{
				status: corev1.ContainerStatus{
					ImageID: "sha256:sampleimagehash2",
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "empty skip list",
			fields: fields{
				verifyFunction: nil,
				skippedImages:  nil,
			},
			args: args{
				status: corev1.ContainerStatus{
					ImageID: "sha256:sampleimagehash",
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "image has no imageID",
			fields: fields{
				verifyFunction: nil,
				skippedImages: map[string][]string{
					"sha256:sampleimagehash": {
						"image-signature-subject:sampleimage",
					},
					"sha256:sampleimagehash2": {
						"image-signature-subject:sampleimage2",
					},
					"sha256:sampleimagehash3": {
						"image-signature-subject:sampleimage3",
					},
				},
			},
			args: args{
				status: corev1.ContainerStatus{
					ImageID: "",
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := Sigstoreimpl{
				verifyFunction: tt.fields.verifyFunction,
				skippedImages:  tt.fields.skippedImages,
			}
			got, err := sigstore.SkipImage(tt.args.status)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.SkipImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.SkipImage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getSignatureSubject(t *testing.T) {
	type args struct {
		signature oci.Signature
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "single image signature",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			want: "spirex@hpe.com",
		},
		{
			name: "empty signature array",
			args: args{signature: nil},
			want: "",
		},
		{
			name: "single image signature, no payload",
			args: args{
				signature: noPayloadSignature{},
			},
			want: "",
		},
		{
			name: "single image signature, no certs",
			args: args{
				signature: &noCertSignature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			want: "",
		},
		{
			name: "single image signature,garbled subject in signature",
			args: args{
				signature: &signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "s\\\\||as\0\0aasdasd/....???/.>wd12<><,,,><{}{pirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSignatureSubject(tt.args.signature); got != tt.want {
				t.Errorf("getSignatureSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_AddSkippedImage(t *testing.T) {
	type fields struct {
		verifyFunction           func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		validateImageRefFunction func(name.Reference) (bool, error)
		skippedImages            map[string]([]string)
	}
	type args struct {
		imageID   string
		selectors []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string][]string
	}{
		{
			name: "add skipped image to empty map",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
				validateImageRefFunction: func(name.Reference) (bool, error) {
					return true, nil
				},
				skippedImages: map[string][]string{},
			},
			args: args{
				imageID: "sha256:sampleimagehash",
				selectors: []string{
					"image-signature-subject:sampleimage",
				},
			},
			want: map[string][]string{
				"sha256:sampleimagehash": {
					"image-signature-subject:sampleimage",
				},
			},
		},
		{
			name: "add skipped image",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
				validateImageRefFunction: func(name.Reference) (bool, error) {
					return true, nil
				},
				skippedImages: map[string]([]string){
					"sha256:sampleimagehash1": {
						"image-signature-subject:sampleimage1",
					},
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash",
				selectors: []string{
					"image-signature-subject:sampleimage",
				},
			},
			want: map[string][]string{
				"sha256:sampleimagehash": {
					"image-signature-subject:sampleimage",
				},
				"sha256:sampleimagehash1": {
					"image-signature-subject:sampleimage1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := Sigstoreimpl{
				verifyFunction:           tt.fields.verifyFunction,
				validateImageRefFunction: tt.fields.validateImageRefFunction,
				skippedImages:            tt.fields.skippedImages,
			}
			sigstore.AddSkippedImage(tt.args.imageID, tt.args.selectors)
			if !reflect.DeepEqual(sigstore.skippedImages, tt.want) {
				t.Errorf("sigstore.skippedImages = %v, want %v", sigstore.skippedImages, tt.want)
			}
		})
	}
}
