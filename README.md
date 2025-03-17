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
