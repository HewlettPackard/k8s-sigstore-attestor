package sigstore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type Sigstore interface {
	FetchSignaturePayload(imageName string, rekorURL string) ([]cosign.SignedPayload, error)
	ExtractselectorOfSignedImage(payload []cosign.SignedPayload) string
}

type Sigstoreimpl struct {
	verifyFunction func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]cosign.SignedPayload, error)
}

func New() Sigstore {
	return &Sigstoreimpl{
		verifyFunction: cosign.Verify,
	}
}

func (sigstore Sigstoreimpl) FetchSignaturePayload(imageName string, rekorURL string) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		message := fmt.Sprint("Error parsing the image reference: ", err.Error())
		return nil, errors.New(message)
	}

	ctx := context.Background()
	co := &cosign.CheckOpts{}
	co.RekorURL = rekorURL
	co.RootCerts = fulcio.GetRoots()

	sigRepo, err := cli.TargetRepositoryForImage(ref)
	if err != nil {
		message := fmt.Sprint("TargetRepositoryForImage returned error: ", err.Error())
		return nil, errors.New(message)
	}
	co.SignatureRepo = sigRepo

	verified, err := sigstore.verifyFunction(ctx, ref, co)

	if err != nil {
		message := fmt.Sprint("Error verifying signature: ", err.Error())
		return nil, errors.New(message)
	}
	return verified, nil
}

func (Sigstoreimpl) ExtractselectorOfSignedImage(payload []cosign.SignedPayload) string {
	var selector string
	// Payload can be empty if the attestor fails to retrieve it
	// In a non-strict mode this method should be reached and return
	// an empty selector
	if payload != nil {
		// verify which subject
		selector = getSubjectImage(payload)
	}

	// return subject as selector
	return selector
}

type Subject struct {
	Subject string
}

type Optional struct {
	Optional Subject
}

func getOnlySubject(payload string) string {
	var selector []Optional
	err := json.Unmarshal([]byte(payload), &selector)

	if err != nil {
		log.Println("Error decoding the payload:", err.Error())
		return ""
	}

	re := regexp.MustCompile(`[{}]`)

	subject := fmt.Sprintf("%s", selector[0])
	subject = re.ReplaceAllString(subject, "")

	return subject
}

func getSubjectImage(verified []cosign.SignedPayload) string {
	var outputKeys []payload.SimpleContainerImage
	for _, vp := range verified {
		ss := payload.SimpleContainerImage{}

		err := json.Unmarshal(vp.Payload, &ss)
		if err != nil {
			log.Println("Error decoding the payload:", err.Error())
			return ""
		}

		if vp.Cert != nil {
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["Subject"] = certSubject(vp.Cert)
		}

		outputKeys = append(outputKeys, ss)
	}
	b, err := json.Marshal(outputKeys)
	if err != nil {
		log.Println("Error generating the output:", err.Error())
		return ""
	}

	subject := getOnlySubject(string(b))

	return subject
}

func certSubject(c *x509.Certificate) string {
	switch {
	case c.EmailAddresses != nil:
		return c.EmailAddresses[0]
	case c.URIs != nil:
		return c.URIs[0].String()
	}
	return ""
}
