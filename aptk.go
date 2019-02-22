package aptk

import (
	"github.com/aws/aws-sdk-go/aws/corehandlers"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
)

const (
	errFailedToCreateSignature       = "failed to preapre signature for request"
	errFailedToRequestCallerIdentity = "failed to request caller identity"
	pncAPIChangedTooMuch             = `"Authorization" header is set despite removing signer from chain - this library is broken now`
)

const (
	// Authorization denotes the key for the Authorization header of a POST request to GetCallerIdentity
	Authorization = "Authorization"

	// Date denotes the key for the Date header of a POST request to GetCallerIdentity
	Date = "X-Amz-Date"
)

// Tuple represents the Authorization tuple requires by Parse(). Note that this
// requires extracting the appropriate values from a signed request object, NOT
// from a presigned URL which differ structurally (e.g. through different signed
// headers such as content length and type, having no body body etc.) and there
// require different signatures.
//
// Example for an Authorization value: AWS4-HMAC-SHA256 Credential=AKIAJW.../20190221/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date, Signature=abcd...
// Example for a Date value: 20190221T211905Z
type Tuple struct {
	Authorization string
	Date          string
}

// Parse will get an external callers identity based on the given authorization
// tuple.
func Parse(client *sts.STS, tuple *Tuple) (*sts.GetCallerIdentityOutput, error) {

	var headers = map[string]string{
		Authorization:  tuple.Authorization,
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		Date:           tuple.Date,
	}

	req, res := client.GetCallerIdentityRequest(nil)

	// the alternative here would have been to "just" remove "v4.SignRequestHandler" - this choice basically makes this usage safer against a renaming of the v4 signer / new signer additions and less safe towards the addition of critical future core handlers

	req.Handlers.Sign.Clear()
	req.Handlers.Sign.SetFrontNamed(corehandlers.BuildContentLengthHandler)

	{

		// make extra sure we're not signing with a local principal here

		req.Sign()

		if auth := req.HTTPRequest.Header.Get(Authorization); auth != "" {
			panic(pncAPIChangedTooMuch)
		}

	}

	for k, v := range headers {
		req.HTTPRequest.Header.Set(k, v)
	}

	if err := req.Send(); err != nil {
		return nil, errors.Wrapf(err, errFailedToRequestCallerIdentity)
	}

	return res, nil

}

// Prepare extracts the tuple required for Parse. This should be easily
// reproducible in other SDK environments.
func Prepare(client *sts.STS) (*Tuple, error) {

	req, _ := client.GetCallerIdentityRequest(nil)

	if err := req.Sign(); err != nil {
		return nil, errors.Wrapf(err, errFailedToCreateSignature)
	}

	return &Tuple{
		Authorization: req.HTTPRequest.Header.Get(Authorization),
		Date:          req.HTTPRequest.Header.Get(Date),
	}, nil

}
