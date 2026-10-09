# OAuth DCR Controller

Create a `DynamicClientRegistration` (`dcr`) to register an OAuth client with
your Tailscale identity provider's Dynamic Client Registration endpoint. The
controller stores the returned credentials in a Kubernetes Secret in the same
namespace as the resource.

## Install

Each [release](https://github.com/goyongi/oauth-dcr-controller/releases)
publishes an `install.yaml` containing the CRD, RBAC, and controller
Deployment (image `ghcr.io/goyongi/oauth-dcr-controller`). Apply the one for
the version you want:

```sh
kubectl apply -f https://github.com/goyongi/oauth-dcr-controller/releases/download/vX.Y.Z/install.yaml
```

To uninstall, delete all `dcr` resources first and wait for them to be
removed (the controller must be running to clear their finalizers), then:

```sh
kubectl delete -f https://github.com/goyongi/oauth-dcr-controller/releases/download/vX.Y.Z/install.yaml
```

## Create a registration

If the registration endpoint requires an initial access token, store it in a
Secret in the resource's namespace. The controller reads the configured key
(`token` by default) and sends it as a bearer token:

```sh
kubectl create secret generic dcr-initial-token \
  -n my-app --from-literal=token='<initial-access-token>'
```

Create a `DynamicClientRegistration`, using the DCR endpoint configured for
your Tailscale IdP and metadata accepted by that IdP:

```yaml
apiVersion: oauth.goyongi.com/v1alpha1
kind: DynamicClientRegistration
metadata:
  name: my-client
  namespace: my-app
spec:
  registrationEndpoint: https://idp.example.ts.net/register
  # Omit initialAccessTokenRef if the endpoint does not require a token.
  initialAccessTokenRef:
    name: dcr-initial-token
    key: token
  # Optional; defaults to the resource name.
  credentialsSecretName: my-client-credentials
  client:
    clientName: My application
    redirectURIs:
      - https://app.example.com/oauth/callback
    grantTypes:
      - authorization_code
      - refresh_token
    responseTypes:
      - code
    tokenEndpointAuthMethod: client_secret_basic
    scope: "openid profile email"
    contacts:
      - platform@example.com
```

The endpoint URL above is an example; use the registration endpoint for your
Tailscale IdP. `spec.client` supports `redirectURIs`,
`tokenEndpointAuthMethod`, `grantTypes`, `responseTypes`, `clientName`,
`clientURI`, `logoURI`, `scope`, `contacts`, `tosURI`, `policyURI`, `jwksURI`,
`softwareID`, and `softwareVersion`. Use `extraMetadata` for additional
string-valued metadata supported by the IdP.

## Check registration and use credentials

Registration succeeds when the resource's `Ready` condition becomes `True`.
The issued client ID is shown in status; client secrets and registration access
tokens are not.

```sh
kubectl get dcr my-client -n my-app
kubectl describe dcr my-client -n my-app
```

The credentials Secret is named by `credentialsSecretName`, or by the resource
name when that field is omitted. It may contain:

- `client_id`
- `client_secret` (not present for public clients or when not returned)
- `registration_access_token` and `registration_client_uri` (when returned)
- `registration_response` (the full response; may include credentials)

Treat the entire Secret as sensitive. Configure your application to consume
the Secret using its usual Kubernetes secret mechanism.

## Important behavior

- Registration is performed once. Editing `spec.client` after registration
  does not update the client at the IdP.
- To register a new client, delete the `dcr`, wait for it to be removed, then
  create it again. The controller attempts upstream cleanup on deletion if the
  IdP returned a management URL and access token; cleanup failure does not
  prevent Kubernetes deletion.
- Deleting the `dcr` also deletes its owned credentials Secret. The controller
  does not rotate credentials.

## Troubleshooting

If `Ready` is `False`, inspect its reason and message with
`kubectl describe dcr my-client -n my-app`. Common causes are an incorrect or
unreachable endpoint, a missing or
incorrect initial-token Secret/key, or metadata rejected by the IdP. The
controller retries failed registrations. Check the controller manager logs for
the underlying error.
