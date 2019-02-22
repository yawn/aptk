# AWS Principal Token (`aptk`)

[![Go Report Card](https://goreportcard.com/badge/github.com/yawn/aptk)](https://goreportcard.com/report/github.com/yawn/aptk)

An `aptk` is a simple implementation of the extraction (which should be
portable among SDK implementations) and parsing logic for the authorization
parts of an STS `GetCallerIdentity` call. This makes it possible to implement
flows where Alice can prove to Bob that can she act as a certain principal (e.g.
a role or an IAM user).

For this Alice extracts the `Authorization` and `Date` headers from a signed request
and passes those to Bob. Bob builds his own request, exchanges thoses headers
and calls STS with the SDK. Depending on the principal, the results should
match the standard [outcomes from STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) yielding
information about the principal type, account ID and possibly the username
(depending on the principal type).

## Usage in `go`

```
package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/yawn/aptk"
)

func main() {

	client := sts.New(session.New(&aws.Config{}))

	// Alice prepares the call and extracts the appropriate headers
	t, err := aptk.Prepare(client)

	if err != nil {
		panic(err)
	}

	// Bob receives those headers, builds a *Token and parses them
	res, err := aptk.Parse(client, t)

	if err != nil {
		panic(err)
	}

	fmt.Println(*res)

}
```
