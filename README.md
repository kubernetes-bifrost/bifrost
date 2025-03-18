# Bifröst

<img src="./docs/img/logo.jpg" alt="Bifröst" width="300" height="300" />

Bifröst helps you get secret-less access on cloud providers by leveraging the
Kubernetes built-in OpenID Connect (OIDC) token issuer for service accounts.

The project has two main goals:

* Provide Kubernetes users with an infrastructure component that can securely
  fetch temporary tokens for applications so they can access cloud resources
  without requiring any secrets to be configured.
* Provide Kubernetes ecosystem maintainers with a secure and reliable library
  for implementing the above functionality in their own controllers.

## Library Usage

Install the main Go module and the Go modules of the providers you want to use
in your controller. Each provider is distributed in its own module so you need
only to install the ones you need.

```shell
$ go get github.com/kubernetes-bifrost/bifrost
$ go get github.com/kubernetes-bifrost/bifrost/providers/aws
$ go get github.com/kubernetes-bifrost/bifrost/providers/azure
$ go get github.com/kubernetes-bifrost/bifrost/providers/gcp
$ 
```

Then use the library like this:

```go
import (
	bifröst "github.com/kubernetes-bifrost/bifrost"
	"github.com/kubernetes-bifrost/bifrost/providers/aws"
	"github.com/kubernetes-bifrost/bifrost/providers/azure"
	"github.com/kubernetes-bifrost/bifrost/providers/gcp"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var providers = map[string]bifröst.Provider{
	aws.ProviderName:   aws.Provider{},
	azure.ProviderName: azure.Provider{},
	gcp.ProviderName:   gcp.Provider{},
}

func main() {
	providerName := "" // Get the provider name from somewhere.

	provider, ok := providers[providerName]
	if !ok {
		// Handle the error.
	}

	var serviceAccountRef client.ObjectKey // Get the service account reference from somewhere.
	var client client.Client // Get a controller-runtime client from somewhere.

	token, err := bifröst.GetToken(ctx, provider,
		bifröst.WithServiceAccount(serviceAccountRef, client))
	if err != nil {
		// Handle the error.
	}

	// Use the token.
}
```

The `controller-runtime` client needs the follow permissions:

* Get the involved service account.
* Create tokens for the involved service account.
* Get a secret containing settings for an HTTP/S proxy if configured on the service account.
