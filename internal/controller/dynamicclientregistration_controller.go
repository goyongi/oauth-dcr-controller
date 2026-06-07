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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	oauthv1alpha1 "goyongi.com/oauth-dcr-controller/api/v1alpha1"
)

const (
	// finalizerName guards best-effort cleanup of the upstream client
	// registration (RFC 7592) before the resource is removed.
	finalizerName = "oauth.goyongi.com/registration-cleanup"

	// conditionReady is the condition type set once the client is registered and
	// its credentials are persisted to the target Secret.
	conditionReady = "Ready"

	// Keys written into the credentials Secret's data.
	secretKeyClientID       = "client_id"
	secretKeyClientSecret   = "client_secret"
	secretKeyRegAccessToken = "registration_access_token" // #nosec G101 -- map key, not a credential
	secretKeyRegClientURI   = "registration_client_uri"
	secretKeyResponse       = "registration_response"
)

// DynamicClientRegistrationReconciler reconciles a DynamicClientRegistration object
type DynamicClientRegistrationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// HTTPClient is used for the registration and management requests. When nil,
	// http.DefaultClient is used. Injectable for testing.
	HTTPClient *http.Client
}

// +kubebuilder:rbac:groups=oauth.goyongi.com,resources=dynamicclientregistrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=oauth.goyongi.com,resources=dynamicclientregistrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=oauth.goyongi.com,resources=dynamicclientregistrations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile registers an OAuth 2.0 client via RFC 7591 Dynamic Client
// Registration and persists the issued credentials into a Secret.
//
// Idempotency: the credentials Secret is the source of truth. If a Secret with a
// client_id already exists, the client is considered registered and is not
// re-registered. Because RFC 7591 registration is a non-idempotent POST without
// an idempotency key, the controller registers at most once per resource;
// edits to spec.client after registration are NOT propagated upstream (that
// would require RFC 7592 update support, out of scope here). To re-register,
// delete and recreate the resource.
func (r *DynamicClientRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var dcr oauthv1alpha1.DynamicClientRegistration
	if err := r.Get(ctx, req.NamespacedName, &dcr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	secretName := dcr.Spec.CredentialsSecretName
	if secretName == "" {
		secretName = dcr.Name
	}

	// Handle deletion: best-effort upstream cleanup, then drop the finalizer.
	if !dcr.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &dcr, secretName)
	}

	// Ensure the finalizer is present before doing any external work.
	if controllerutil.AddFinalizer(&dcr, finalizerName) {
		if err := r.Update(ctx, &dcr); err != nil {
			return ctrl.Result{}, err
		}
		// The update re-triggers reconciliation; continue on the next pass.
		return ctrl.Result{}, nil
	}

	// Idempotency guard: a Secret already holding a client_id means we have
	// registered before. Reconcile status from the Secret and stop.
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: dcr.Namespace, Name: secretName}, secret)
	switch {
	case err == nil:
		if len(secret.Data[secretKeyClientID]) > 0 {
			return ctrl.Result{}, r.reconcileRegisteredStatus(ctx, &dcr, secret)
		}
		// Secret exists without a client_id: fall through and (re)register.
	case apierrors.IsNotFound(err):
		// No Secret yet: register.
	default:
		return ctrl.Result{}, err
	}

	return r.reconcileRegister(ctx, &dcr, secretName)
}

// reconcileRegister performs the registration and persists credentials. Ordering
// is deliberate: POST -> write Secret -> update status. If the status update
// fails, the next reconcile observes the Secret and does not re-register.
func (r *DynamicClientRegistrationReconciler) reconcileRegister(
	ctx context.Context, dcr *oauthv1alpha1.DynamicClientRegistration, secretName string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	token, err := r.resolveInitialAccessToken(ctx, dcr)
	if err != nil {
		return ctrl.Result{}, r.fail(ctx, dcr, "TokenResolutionFailed", err)
	}

	body, err := buildRegistrationRequest(dcr.Spec.Client)
	if err != nil {
		return ctrl.Result{}, r.fail(ctx, dcr, "InvalidRequest", err)
	}

	respBody, status, err := r.register(ctx, dcr.Spec.RegistrationEndpoint, token, body)
	if err != nil {
		return ctrl.Result{}, r.fail(ctx, dcr, "RegistrationRequestFailed", err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return ctrl.Result{}, r.fail(ctx, dcr, "RegistrationRejected",
			fmt.Errorf("registration endpoint returned %d: %s", status, truncate(respBody, 256)))
	}

	var reg registrationResponse
	if err := json.Unmarshal(respBody, &reg); err != nil {
		return ctrl.Result{}, r.fail(ctx, dcr, "InvalidResponse",
			fmt.Errorf("decoding registration response: %w", err))
	}
	if reg.ClientID == "" {
		return ctrl.Result{}, r.fail(ctx, dcr, "InvalidResponse",
			fmt.Errorf("registration response missing client_id"))
	}

	// Write the Secret first: it is the durable record of a successful
	// registration and the idempotency guard for future reconciles.
	if err := r.upsertCredentialsSecret(ctx, dcr, secretName, respBody, &reg); err != nil {
		return ctrl.Result{}, r.fail(ctx, dcr, "SecretWriteFailed", err)
	}

	applyRegistrationToStatus(dcr, &reg, secretName)
	meta.SetStatusCondition(&dcr.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: dcr.Generation,
		Reason:             "Registered",
		Message:            "Client registered and credentials stored",
	})
	if err := r.Status().Update(ctx, dcr); err != nil {
		// The Secret is already written; the next reconcile will not re-register.
		return ctrl.Result{}, err
	}

	log.Info("Registered OAuth client", "clientID", reg.ClientID, "secret", secretName)
	return ctrl.Result{}, nil
}

// reconcileRegisteredStatus refreshes status from the credentials Secret (the
// source of truth) without re-registering. It is a no-op once status already
// reflects the registration, to avoid update churn in the steady state.
func (r *DynamicClientRegistrationReconciler) reconcileRegisteredStatus(
	ctx context.Context, dcr *oauthv1alpha1.DynamicClientRegistration, secret *corev1.Secret,
) error {
	var reg registrationResponse
	if raw := secret.Data[secretKeyResponse]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &reg)
	}
	if reg.ClientID == "" {
		reg.ClientID = string(secret.Data[secretKeyClientID])
		reg.RegistrationClientURI = string(secret.Data[secretKeyRegClientURI])
	}

	if meta.IsStatusConditionTrue(dcr.Status.Conditions, conditionReady) &&
		dcr.Status.ClientID == reg.ClientID &&
		dcr.Status.ObservedGeneration == dcr.Generation {
		return nil
	}

	applyRegistrationToStatus(dcr, &reg, secret.Name)
	meta.SetStatusCondition(&dcr.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: dcr.Generation,
		Reason:             "Registered",
		Message:            "Client already registered",
	})
	return r.Status().Update(ctx, dcr)
}

// reconcileDelete performs best-effort upstream cleanup (RFC 7592) and removes
// the finalizer. Upstream failures never wedge deletion. The credentials Secret
// is garbage-collected via its owner reference.
func (r *DynamicClientRegistrationReconciler) reconcileDelete(
	ctx context.Context, dcr *oauthv1alpha1.DynamicClientRegistration, secretName string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling deletion", "secret", secretName)

	if !controllerutil.ContainsFinalizer(dcr, finalizerName) {
		// Nothing to clean up: either we never added the finalizer or it was
		// already removed on a prior pass.
		log.Info("No registration-cleanup finalizer present; skipping upstream cleanup")
		return ctrl.Result{}, nil
	}

	// If credentials secret holds the RFC 7592 management URI, perform cleanup
	regClientURI := ""
	token := ""
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: dcr.Namespace, Name: secretName}, secret); err != nil {
		// Gone or unreadable: either way we have no credentials for cleanup.
		// Don't wedge deletion; log and drop the finalizer below.
		log.Error(err, "Could not read credentials Secret during deletion; skipping upstream cleanup",
			"secret", secretName)
	} else {
		regClientURI = string(secret.Data[secretKeyRegClientURI])
		token = string(secret.Data[secretKeyRegAccessToken])
	}

	if regClientURI == "" {
		// No RFC 7592 management URI: the authorization server did not return one
		// at registration (client management unsupported), so there is nothing to
		// DELETE. This is the common reason upstream cleanup "does nothing".
		log.Info("No registration_client_uri in credentials Secret; skipping upstream RFC 7592 delete",
			"secret", secretName, "hasRegAccessToken", token != "")
	} else {
		status, err := r.deleteRegistration(ctx, regClientURI, token)
		switch {
		case err != nil:
			// Cleanup is best effort and must not block deletion.
			log.Error(err, "Failed to delete upstream client registration; removing finalizer anyway",
				"registrationClientURI", regClientURI, "httpStatus", status)
		case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
			// Tolerated, but not an actual delete: the client may still exist
			// upstream (405 = server does not implement RFC 7592 DELETE).
			log.Info("Upstream registration not deleted by server (no-op status); client may still exist upstream",
				"registrationClientURI", regClientURI, "httpStatus", status)
		default:
			log.Info("Deleted upstream client registration",
				"registrationClientURI", regClientURI, "httpStatus", status)
		}
	}

	controllerutil.RemoveFinalizer(dcr, finalizerName)
	if err := r.Update(ctx, dcr); err != nil {
		log.Error(err, "Failed to remove registration-cleanup finalizer")
		return ctrl.Result{}, err
	}
	log.Info("Removed registration-cleanup finalizer; deletion can proceed")
	return ctrl.Result{}, nil
}

// resolveInitialAccessToken reads the bearer token referenced by
// spec.initialAccessTokenRef, if set.
func (r *DynamicClientRegistrationReconciler) resolveInitialAccessToken(
	ctx context.Context, dcr *oauthv1alpha1.DynamicClientRegistration,
) (string, error) {
	ref := dcr.Spec.InitialAccessTokenRef
	if ref == nil {
		return "", nil
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: dcr.Namespace, Name: ref.Name}, secret); err != nil {
		return "", fmt.Errorf("reading initial access token Secret %q: %w", ref.Name, err)
	}
	val, ok := secret.Data[key]
	if !ok || len(val) == 0 {
		return "", fmt.Errorf("initial access token Secret %q has no data at key %q", ref.Name, key)
	}
	return string(val), nil
}

// upsertCredentialsSecret creates or updates the Secret holding the issued
// credentials, owned by the DynamicClientRegistration for garbage collection.
func (r *DynamicClientRegistrationReconciler) upsertCredentialsSecret(
	ctx context.Context, dcr *oauthv1alpha1.DynamicClientRegistration,
	name string, respBody []byte, reg *registrationResponse,
) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: dcr.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := controllerutil.SetControllerReference(dcr, secret, r.Scheme); err != nil {
			return err
		}
		if secret.Type == "" {
			secret.Type = corev1.SecretTypeOpaque
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[secretKeyClientID] = []byte(reg.ClientID)
		setOrDelete(secret.Data, secretKeyClientSecret, reg.ClientSecret)
		setOrDelete(secret.Data, secretKeyRegAccessToken, reg.RegistrationAccessToken)
		setOrDelete(secret.Data, secretKeyRegClientURI, reg.RegistrationClientURI)
		secret.Data[secretKeyResponse] = respBody
		return nil
	})
	return err
}

// fail records a failure on the Ready condition and returns the original error
// so the request is requeued with backoff. The status update is best effort.
func (r *DynamicClientRegistrationReconciler) fail(
	ctx context.Context, dcr *oauthv1alpha1.DynamicClientRegistration, reason string, cause error,
) error {
	logf.FromContext(ctx).Error(cause, "Registration reconcile failed", "reason", reason)
	meta.SetStatusCondition(&dcr.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: dcr.Generation,
		Reason:             reason,
		Message:            cause.Error(),
	})
	dcr.Status.ObservedGeneration = dcr.Generation
	if err := r.Status().Update(ctx, dcr); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update status after reconcile failure")
	}
	return cause
}

// applyRegistrationToStatus copies registration results into status. Secrets
// (client_secret, registration_access_token) are never written here.
func applyRegistrationToStatus(
	dcr *oauthv1alpha1.DynamicClientRegistration, reg *registrationResponse, secretName string,
) {
	dcr.Status.ClientID = reg.ClientID
	dcr.Status.RegistrationClientURI = reg.RegistrationClientURI
	dcr.Status.CredentialsSecretName = secretName
	dcr.Status.ObservedGeneration = dcr.Generation
	if reg.ClientIDIssuedAt > 0 {
		t := metav1.Unix(reg.ClientIDIssuedAt, 0)
		dcr.Status.ClientIDIssuedAt = &t
	}
	if reg.ClientSecretExpiresAt > 0 {
		t := metav1.Unix(reg.ClientSecretExpiresAt, 0)
		dcr.Status.ClientSecretExpiresAt = &t
	} else {
		dcr.Status.ClientSecretExpiresAt = nil
	}
}

// setOrDelete writes a non-empty value into the data map, or removes the key
// when the value is empty (e.g. public clients have no client_secret).
func setOrDelete(data map[string][]byte, key, value string) {
	if value == "" {
		delete(data, key)
		return
	}
	data[key] = []byte(value)
}

// truncate bounds a byte slice for safe inclusion in a status message.
func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// SetupWithManager sets up the controller with the Manager.
func (r *DynamicClientRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&oauthv1alpha1.DynamicClientRegistration{}).
		Owns(&corev1.Secret{}).
		Named("dynamicclientregistration").
		Complete(r)
}
