package sigstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	rekor "github.com/sigstore/rekor/pkg/generated/client"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	corev1 "k8s.io/api/core/v1"
)

type Sigstore interface {
	FetchImageSignatures(imageName string, rekorURL string) ([]oci.Signature, error)
	SelectorValuesFromSignature(oci.Signature) []string
	ExtractSelectorsFromSignatures(signatures []oci.Signature) []string
	SkipImage(status corev1.ContainerStatus) ([]string, error)
	AddSkippedImage(imageID string, selectors []string)
	ClearSkipList()
}

type Sigstoreimpl struct {
	verifyFunction           func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	validateImageRefFunction func(name.Reference) (bool, error)
	skippedImages            map[string]([]string)
}

func New() Sigstore {
	return &Sigstoreimpl{
		verifyFunction:           cosign.VerifyImageSignatures,
		validateImageRefFunction: ValidateImage,
		skippedImages:            nil,
	}
}

// FetchImageSignatures retrieves the signature payload from the specified image
func (sigstore Sigstoreimpl) FetchImageSignatures(imageName string, rekorURL string) ([]oci.Signature, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		message := fmt.Sprint("Error parsing image reference: ", err.Error())
		return nil, errors.New(message)
	}

	_, err = sigstore.validateImageRefFunction(ref)
	if err != nil {
		message := fmt.Sprint("Could not validate image reference digest: ", err.Error())
		log.Println(message)
		return nil, errors.New(message)
	}

	co := &cosign.CheckOpts{}
	if rekorURL != "" {
		rekorURI, err := url.Parse(rekorURL)
		if err != nil {
			message := fmt.Sprint("Error parsing rekor URI: ", err.Error())
			return nil, errors.New(message)
		}
		if rekorURI.Scheme != "" && rekorURI.Scheme != "https" {
			return nil, errors.New("Invalid rekor URL Scheme: " + rekorURI.Scheme)
		}
		if rekorURI.Host == "" {
			return nil, errors.New("Invalid rekor URL Host: " + rekorURI.Host)
		}
		co.RekorClient = rekor.NewHTTPClientWithConfig(nil, rekor.DefaultTransportConfig().WithBasePath(rekorURI.Path).WithHost(rekorURI.Host))
	} else {
		co.RekorClient = rekor.NewHTTPClientWithConfig(nil, rekor.DefaultTransportConfig())
	}
	co.RootCerts = fulcio.GetRoots()

	ctx := context.Background()
	sigs, ok, err := sigstore.verifyFunction(ctx, ref, co)
	if err != nil {
		message := fmt.Sprint("Error verifying signature: ", err.Error())
		return nil, errors.New(message)
	}
	if !ok {
		message := "Bundle not verified for " + imageName
		return nil, errors.New(message)
	}

	return sigs, nil
}

func (sigstore Sigstoreimpl) ExtractSelectorsFromSignatures(signatures []oci.Signature) []string {
	// Payload can be empty if the attestor fails to retrieve it
	if signatures == nil {
		return nil
	}
	// TODO: add flag for verified stuff?
	var selectors []string
	for _, sig := range signatures {
		// verify which subject
		sigSelectors := sigstore.SelectorValuesFromSignature(sig)
		if sigSelectors != nil {
			selectors = append(selectors, sigSelectors...)
		}
	}
	return selectors
}

func getSignatureSubject(signature oci.Signature) string {
	if signature == nil {
		return ""
	}
	ss := payload.SimpleContainerImage{}
	pl, err := signature.Payload()
	if err != nil {
		log.Println("Error accessing the payload:", err.Error())
		return ""
	}
	err = json.Unmarshal(pl, &ss)
	if err != nil {
		log.Println("Error decoding the payload:", err.Error())
		return ""
	}
	cert, err := signature.Cert()
	if err != nil {
		log.Println("Error accessing the certificate:", err.Error())
		return ""
	}

	subject := ""
	if ss.Optional != nil {
		subjString := ss.Optional["subject"]
		if _, ok := subjString.(string); ok {
			subject = subjString.(string)
		}
	}
	if cert != nil {
		subject = certSubject(cert)
	}

	return subject
}

func certSubject(c *x509.Certificate) string {
	switch {
	case c == nil:
		return ""
	case c.EmailAddresses != nil:
		return c.EmailAddresses[0]
	case c.URIs != nil:
		// removing leading '//' from c.URIs[0].String()
		re := regexp.MustCompile(`^\/*(?P<email>.*)`)
		return re.ReplaceAllString(c.URIs[0].String(), "$email")
	}
	return ""
}

func (sigstore Sigstoreimpl) SkipImage(status corev1.ContainerStatus) ([]string, error) {
	if sigstore.skippedImages != nil {
		selectors, ok := sigstore.skippedImages[status.ImageID]
		if ok {
			return selectors, nil
		}
	}
	return nil, nil
}

func (sigstore Sigstoreimpl) SelectorValuesFromSignature(signature oci.Signature) []string {
	subject := getSignatureSubject(signature)

	if subject != "" {
		return []string{
			fmt.Sprintf("image-signature-subject:%s", subject),
		}
	} else {
		return nil
	}
}

func (sigstore Sigstoreimpl) AddSkippedImage(imageHash string, selectors []string) {
	sigstore.skippedImages[imageHash] = selectors
}

func (sigstore Sigstoreimpl) ClearSkipList() {
	for k := range sigstore.skippedImages {
		delete(sigstore.skippedImages, k)
	}
}

func ValidateImage(ref name.Reference) (bool, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return false, err
	}

	hash, _, err := v1.SHA256(bytes.NewReader(desc.Manifest))
	if err != nil {
		return false, err
	}

	return validateRefDigest(ref, hash.String())
}

func validateRefDigest(ref name.Reference, digest string) (bool, error) {
	if dgst, ok := ref.(name.Digest); ok {
		if dgst.DigestStr() == digest {
			return true, nil
		}
	}

	// do nothing if ref is a Tag
	return false, nil
}
