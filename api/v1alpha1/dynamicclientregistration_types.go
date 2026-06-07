/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecretKeySelector selects a single key from a Secret in the same namespace as
// the referencing DynamicClientRegistration.
type SecretKeySelector struct {
	// name is the name of the Secret.
	// +required
	Name string `json:"name"`

	// key is the key within the Secret's data that holds the value.
	// +kubebuilder:default=token
	// +optional
	Key string `json:"key,omitempty"`
}

// ClientMetadata holds the OAuth 2.0 client metadata submitted to the
// authorization server's registration endpoint, as defined by RFC 7591 §2
// (https://www.rfc-editor.org/rfc/rfc7591#section-2). Authorization servers may
// accept additional metadata members not modeled here; use extraMetadata to
// supply them.
type ClientMetadata struct {
	// redirectURIs is the list of redirection URIs the client uses in
	// redirect-based flows such as the authorization code grant. Sent as the
	// "redirect_uris" registration parameter.
	// +optional
	RedirectURIs []string `json:"redirectURIs,omitempty"`

	// tokenEndpointAuthMethod is the requested client authentication method for
	// the token endpoint, e.g. "client_secret_basic", "client_secret_post",
	// "private_key_jwt", or "none". When "none", the server registers a public
	// client and typically returns no client_secret. Sent as
	// "token_endpoint_auth_method".
	// +optional
	TokenEndpointAuthMethod string `json:"tokenEndpointAuthMethod,omitempty"`

	// grantTypes is the list of OAuth 2.0 grant types the client may use, e.g.
	// "authorization_code", "client_credentials", "refresh_token". Sent as
	// "grant_types".
	// +optional
	GrantTypes []string `json:"grantTypes,omitempty"`

	// responseTypes is the list of OAuth 2.0 response types the client may use,
	// e.g. "code". Sent as "response_types".
	// +optional
	ResponseTypes []string `json:"responseTypes,omitempty"`

	// clientName is a human-readable name for the client. Sent as "client_name".
	// +optional
	ClientName string `json:"clientName,omitempty"`

	// clientURI is a URL of the home page of the client. Sent as "client_uri".
	// +optional
	ClientURI string `json:"clientURI,omitempty"`

	// logoURI is a URL that references a logo for the client. Sent as "logo_uri".
	// +optional
	LogoURI string `json:"logoURI,omitempty"`

	// scope is a space-separated list of scope values the client may request.
	// Sent as "scope".
	// +optional
	Scope string `json:"scope,omitempty"`

	// contacts is a list of ways (typically email addresses) to contact the
	// people responsible for the client. Sent as "contacts".
	// +optional
	Contacts []string `json:"contacts,omitempty"`

	// tosURI is a URL pointing to the client's terms of service. Sent as
	// "tos_uri".
	// +optional
	TosURI string `json:"tosURI,omitempty"`

	// policyURI is a URL pointing to the client's privacy policy. Sent as
	// "policy_uri".
	// +optional
	PolicyURI string `json:"policyURI,omitempty"`

	// jwksURI is a URL referencing the client's JSON Web Key Set document. Sent
	// as "jwks_uri".
	// +optional
	JwksURI string `json:"jwksURI,omitempty"`

	// softwareID is a unique identifier for the client software, stable across
	// deployments and versions. Sent as "software_id".
	// +optional
	SoftwareID string `json:"softwareID,omitempty"`

	// softwareVersion is the version of the client software. Sent as
	// "software_version".
	// +optional
	SoftwareVersion string `json:"softwareVersion,omitempty"`

	// extraMetadata carries additional string-valued registration metadata
	// members that are not modeled explicitly above. Each entry is sent verbatim
	// as a JSON string member of the registration request. Keys here do not
	// override the explicit fields above.
	// +optional
	ExtraMetadata map[string]string `json:"extraMetadata,omitempty"`
}

// DynamicClientRegistrationSpec defines the desired state of DynamicClientRegistration
type DynamicClientRegistrationSpec struct {
	// registrationEndpoint is the URL of the OAuth 2.0 Dynamic Client
	// Registration endpoint (RFC 7591) to which the registration request is
	// sent.
	// +kubebuilder:validation:Pattern=`^https?://.+`
	// +required
	RegistrationEndpoint string `json:"registrationEndpoint"`

	// initialAccessTokenRef optionally references a Secret holding the bearer
	// token ("initial access token") used to authorize the registration
	// request. Required by authorization servers that protect their registration
	// endpoint.
	// +optional
	InitialAccessTokenRef *SecretKeySelector `json:"initialAccessTokenRef,omitempty"`

	// client holds the OAuth 2.0 client metadata submitted to the registration
	// endpoint.
	// +required
	Client ClientMetadata `json:"client"`

	// credentialsSecretName is the name of the Secret, created in the same
	// namespace, that will hold the issued client credentials (client_id,
	// client_secret, registration_access_token, and the full registration
	// response). Defaults to the name of the DynamicClientRegistration resource.
	// +optional
	CredentialsSecretName string `json:"credentialsSecretName,omitempty"`
}

// DynamicClientRegistrationStatus defines the observed state of DynamicClientRegistration.
type DynamicClientRegistrationStatus struct {
	// conditions represent the current state of the DynamicClientRegistration
	// resource. The "Ready" condition is True once the client has been
	// registered with the authorization server and its credentials have been
	// written to the target Secret.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// clientID is the issued OAuth 2.0 client identifier. It is safe to surface
	// in status; the client_secret and registration_access_token are written
	// only to the credentials Secret, never to status.
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// registrationClientURI is the server-provided URL for managing this client
	// registration (RFC 7592), used for best-effort cleanup on deletion.
	// +optional
	RegistrationClientURI string `json:"registrationClientURI,omitempty"`

	// clientIDIssuedAt is the time at which the client identifier was issued.
	// +optional
	ClientIDIssuedAt *metav1.Time `json:"clientIDIssuedAt,omitempty"`

	// clientSecretExpiresAt is the time at which the client secret expires.
	// Absent means the server did not set an expiry (the secret does not
	// expire).
	// +optional
	ClientSecretExpiresAt *metav1.Time `json:"clientSecretExpiresAt,omitempty"`

	// credentialsSecretName is the name of the Secret holding the issued
	// credentials.
	// +optional
	CredentialsSecretName string `json:"credentialsSecretName,omitempty"`

	// observedGeneration is the .metadata.generation that was last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dcr
// +kubebuilder:printcolumn:name="Client ID",type=string,JSONPath=`.status.clientID`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DynamicClientRegistration is the Schema for the dynamicclientregistrations API
type DynamicClientRegistration struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of DynamicClientRegistration
	// +required
	Spec DynamicClientRegistrationSpec `json:"spec"`

	// status defines the observed state of DynamicClientRegistration
	// +optional
	Status DynamicClientRegistrationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DynamicClientRegistrationList contains a list of DynamicClientRegistration
type DynamicClientRegistrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DynamicClientRegistration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DynamicClientRegistration{}, &DynamicClientRegistrationList{})
}
