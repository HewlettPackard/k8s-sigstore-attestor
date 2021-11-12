package main

import (
	"bytes"
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
	"github.com/sirupsen/logrus"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/support/k8s/k8s-workload-registrar/federation"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ControllerConfig struct {
	Log                logrus.FieldLogger
	E                  entryv1.EntryClient
	TrustDomain        string
	Cluster            string
	PodLabel           string
	PodAnnotation      string
	DisabledNamespaces map[string]bool
}

type Controller struct {
	c ControllerConfig
}

// HCLController holds the configuration parsed from HCL
type HCLController struct {
	// RekorURL is the URL for the rekor server to use to verify signatures and public keys
	RekorURL string `hcl:"rekor_url"`
}

func NewController(config ControllerConfig) *Controller {
	return &Controller{
		c: config,
	}
}

func (c *Controller) Initialize(ctx context.Context) error {
	// Todo: could get the payload here at Initialize
	// ensure there is a node registration entry for PSAT nodes in the cluster.
	return c.createEntry(ctx, &types.Entry{
		ParentId: c.makeID("%s", idutil.ServerIDPath),
		SpiffeId: c.nodeID(),
		Selectors: []*types.Selector{
			{Type: "k8s_psat", Value: fmt.Sprintf("cluster:%s", c.c.Cluster)},
		},
	})
}

func (c *Controller) ReviewAdmission(ctx context.Context, ar admv1.AdmissionReview) (*admv1.AdmissionResponse, error) {
	req := ar.Request
	c.c.Log.WithFields(logrus.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"version":   req.Kind.Version,
		"operation": req.Operation,
	}).Debug("ReviewAdmission called")

	if err := c.reviewAdmission(ctx, req); err != nil {
		return nil, err
	}

	return &admv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}, nil
}

// reviewAdmission handles CREATE and DELETE requests for pods in
// non-kubernetes namespaces. Ideally the ValidatingAdmissionWebhook
// configuration has filters in place to restrict the admission requests.
func (c *Controller) reviewAdmission(ctx context.Context, req *admv1.AdmissionRequest) error {
	if _, disabled := c.c.DisabledNamespaces[req.Namespace]; disabled {
		return nil
	}

	if req.Kind != (metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}) {
		c.c.Log.WithFields(logrus.Fields{
			"version": req.Kind.Version,
			"kind":    req.Kind.Kind,
		}).Warn("Admission request received for unhandled object; check filters")
		return nil
	}

	switch req.Operation {
	case admv1.Create:
		pod := new(corev1.Pod)
		if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
			return errs.New("unable to unmarshal %s/%s object: %v", req.Kind.Version, req.Kind.Kind, err)
		}
		return c.createPodEntry(ctx, pod)
	case admv1.Delete:
		return c.deletePodEntry(ctx, req.Namespace, req.Name)
	default:
		c.c.Log.WithFields(logrus.Fields{
			"operation": req.Operation,
		}).Warn("Admission request received for unhandled pod operation; check filters")
	}

	return nil
}

// podSpiffeID returns the desired spiffe ID for the pod, or nil if it should be ignored
func (c *Controller) podSpiffeID(pod *corev1.Pod) *types.SPIFFEID {
	if c.c.PodLabel != "" {
		// the controller has been configured with a pod label. if the pod
		// has that label, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if labelValue, ok := pod.Labels[c.c.PodLabel]; ok {
			return c.makeID("/%s", labelValue)
		}
		return nil
	}

	if c.c.PodAnnotation != "" {
		// the controller has been configured with a pod annotation. if the pod
		// has that annotation, use the value to construct the pod entry. otherwise
		// ignore the pod altogether.
		if annotationValue, ok := pod.Annotations[c.c.PodAnnotation]; ok {
			return c.makeID("/%s", annotationValue)
		}
		return nil
	}

	// the controller has not been configured with a pod label or a pod annotation.
	// create an entry based on the service account.
	return c.makeID("/ns/%s/sa/%s", pod.Namespace, pod.Spec.ServiceAccountName)
}

func getSignaturePayload(image string) ([]cosign.SignedPayload, error) {
	config := new(HCLController)
	ref, err := name.ParseReference(image)
	if err != nil {
		message := fmt.Sprint("Error parsing the image reference: ", err.Error())
		return nil, errors.New(message)
	}

	ctx := context.Background()
	co := &cosign.CheckOpts{}
	co.RekorURL = config.RekorURL
	co.RootCerts = fulcio.GetRoots()

	sigRepo, err := cli.TargetRepositoryForImage(ref)
	if err != nil {
		message := fmt.Sprint("TargetRepositoryForImage returned error: ", err.Error())
		return nil, errors.New(message)
	}
	co.SignatureRepo = sigRepo

	verified, err := cosign.Verify(ctx, ref, co)

	if err != nil {
		message := fmt.Sprint("Error verifying signature: ", err.Error())
		return nil, errors.New(message)
	}
	return verified, nil
}

func (c *Controller) createPodEntry(ctx context.Context, pod *corev1.Pod) error {
	spiffeID := c.podSpiffeID(pod)
	// If we have no spiffe ID for the pod, do nothing
	if spiffeID == nil {
		return nil
	}

	// Todo: get Image Name???
	// If it not signed?
	signedPayload, err := getSignaturePayload("registry.me:5000/spire-agent:latest-local")
	if err != nil {
		log.Println("Error retrieving signature payload: ", err.Error())
	}

	federationDomains := federation.GetFederationDomains(pod)

	return c.createEntry(ctx, &types.Entry{
		ParentId: c.nodeID(),
		SpiffeId: spiffeID,
		Selectors: []*types.Selector{
			namespaceSelector(pod.Namespace),
			podNameSelector(pod.Name),
			subjectSelector(getselectorOfSignedImage(signedPayload)),
		},
		FederatesWith: federationDomains,
	})
}

func (c *Controller) deletePodEntry(ctx context.Context, namespace, name string) error {
	log := c.c.Log.WithFields(logrus.Fields{
		"ns":  namespace,
		"pod": name,
	})

	listResp, err := c.c.E.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{
			BySelectors: &types.SelectorMatch{
				Selectors: []*types.Selector{
					namespaceSelector(namespace),
					podNameSelector(name),
				},
			},
		},
		// Only the ID is needed, which is implicit in the mask.
		OutputMask: &types.EntryMask{},
	})
	if err != nil {
		return errs.New("unable to list pod entries: %v", err)
	}

	log.Info("Deleting pod entries")
	if len(listResp.Entries) > 1 {
		log.WithField("count", len(listResp.Entries)).Warn("Multiple pod entries found to delete")
	}

	entriesToDelete := make([]string, 0, len(listResp.Entries))
	for _, entry := range listResp.Entries {
		entriesToDelete = append(entriesToDelete, entry.Id)
	}

	deleteResp, err := c.c.E.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{
		Ids: entriesToDelete,
	})
	if err != nil {
		return errs.New("unable to delete pod entries: %v", err)
	}

	var errGroup errs.Group
	for _, result := range deleteResp.Results {
		err := errorFromStatus(result.Status)
		switch status.Code(err) {
		case codes.OK, codes.NotFound:
		default:
			log.WithError(err).Error("Failed deleting pod entry")
			errGroup.Add(errs.New("unable to delete entry %q: %v", result.Id, err))
		}
	}
	return errGroup.Err()
}

func (c *Controller) nodeID() *types.SPIFFEID {
	return c.makeID("/k8s-workload-registrar/%s/node", c.c.Cluster)
}

func (c *Controller) makeID(pathFmt string, pathArgs ...interface{}) *types.SPIFFEID {
	return &types.SPIFFEID{
		TrustDomain: c.c.TrustDomain,
		Path:        idutil.FormatPath(pathFmt, pathArgs...),
	}
}

func (c *Controller) createEntry(ctx context.Context, entry *types.Entry) error {
	// ensure there is a node registration entry for PSAT nodes in the cluster.
	log := c.c.Log.WithFields(logrus.Fields{
		"parent_id": entry.ParentId,
		"spiffe_id": entry.SpiffeId,
		"selectors": selectorsField(entry.Selectors),
	})

	resp, err := c.c.E.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
		Entries: []*types.Entry{entry},
	})
	if err != nil {
		log.WithError(err).Error("Failed to create pod entry")
		return err
	}

	// These checks are purely defensive.
	switch {
	case len(resp.Results) > 1:
		return errors.New("batch create response has too many results")
	case len(resp.Results) < 1:
		return errors.New("batch create response result empty")
	}

	err = errorFromStatus(resp.Results[0].Status)
	switch status.Code(err) {
	case codes.OK, codes.AlreadyExists:
		log.Info("Created pod entry")
		return nil
	default:
		log.WithError(err).Error("Failed to create pod entry")
		return err
	}
}

func namespaceSelector(namespace string) *types.Selector {
	return &types.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("ns:%s", namespace),
	}
}

func podNameSelector(podName string) *types.Selector {
	return &types.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("pod-name:%s", podName),
	}
}

func subjectSelector(subjectImage string) *types.Selector {
	return &types.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf("image-signature-subject:%s", subjectImage),
	}
}

func selectorsField(selectors []*types.Selector) string {
	var buf bytes.Buffer
	for i, selector := range selectors {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(selector.Type)
		buf.WriteString(":")
		buf.WriteString(selector.Value)
	}
	return buf.String()
}

func errorFromStatus(s *types.Status) error {
	if s == nil {
		return errors.New("result status is unexpectedly nil")
	}
	return status.Error(codes.Code(s.Code), s.Message)
}

func getselectorOfSignedImage(payload []cosign.SignedPayload) string {
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
