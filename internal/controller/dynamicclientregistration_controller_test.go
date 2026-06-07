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
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	oauthv1alpha1 "goyongi.com/oauth-dcr-controller/api/v1alpha1"
)

// fakeAuthServer is a minimal RFC 7591/7592 authorization server used to drive
// the reconciler in tests. It records what it received and what it returns.
type fakeAuthServer struct {
	server *httptest.Server

	mu              sync.Mutex
	registerCalls   int
	deleteCalls     int
	lastBody        map[string]any
	lastAuthHeader  string
	clientSecret    string // when empty, a public client (no secret) is returned
	secretExpiresAt int64
}

func newFakeAuthServer(clientSecret string, secretExpiresAt int64) *fakeAuthServer {
	f := &fakeAuthServer{clientSecret: clientSecret, secretExpiresAt: secretExpiresAt}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.registerCalls++
		f.lastAuthHeader = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &f.lastBody)

		resp := map[string]any{
			"client_id":                 "generated-client-id",
			"client_id_issued_at":       1700000000,
			"registration_client_uri":   f.server.URL + "/register/clients/generated-client-id",
			"registration_access_token": "reg-access-token",
		}
		if f.clientSecret != "" {
			resp["client_secret"] = f.clientSecret
			resp["client_secret_expires_at"] = f.secretExpiresAt
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/register/clients/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodDelete {
			f.deleteCalls++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeAuthServer) registerURL() string { return f.server.URL + "/register" }
func (f *fakeAuthServer) close()              { f.server.Close() }
func (f *fakeAuthServer) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registerCalls, f.deleteCalls
}

var _ = Describe("DynamicClientRegistration Controller", func() {
	const namespace = "default"

	var (
		ctx        context.Context
		auth       *fakeAuthServer
		reconciler *DynamicClientRegistrationReconciler
	)

	BeforeEach(func() {
		ctx = context.Background()
		auth = newFakeAuthServer("generated-client-secret", 0)
		reconciler = &DynamicClientRegistrationReconciler{
			Client:     k8sClient,
			Scheme:     k8sClient.Scheme(),
			HTTPClient: auth.server.Client(),
		}
	})

	AfterEach(func() {
		auth.close()
	})

	// reconcileUntilReady drives Reconcile repeatedly (the first pass only adds
	// the finalizer) until the resource reports Ready or the cap is hit.
	reconcileUntilReady := func(key types.NamespacedName) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
			g.Expect(err).NotTo(HaveOccurred())
			var got oauthv1alpha1.DynamicClientRegistration
			g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			g.Expect(meta.IsStatusConditionTrue(got.Status.Conditions, conditionReady)).To(BeTrue())
		}).Should(Succeed())
	}

	newDCR := func(name string, spec oauthv1alpha1.DynamicClientRegistrationSpec) types.NamespacedName {
		GinkgoHelper()
		dcr := &oauthv1alpha1.DynamicClientRegistration{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, dcr)).To(Succeed())
		return types.NamespacedName{Name: name, Namespace: namespace}
	}

	It("registers the client, stores credentials in a Secret, and sets status", func() {
		key := newDCR("confidential-client", oauthv1alpha1.DynamicClientRegistrationSpec{
			RegistrationEndpoint:  auth.registerURL(),
			CredentialsSecretName: "confidential-client-creds",
			Client: oauthv1alpha1.ClientMetadata{
				ClientName:              "Example App",
				RedirectURIs:            []string{"https://app.example.com/callback"},
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "client_secret_basic",
				Scope:                   "openid profile",
			},
		})
		DeferCleanup(func() { deleteAndDrain(ctx, reconciler, key) })

		reconcileUntilReady(key)

		By("mapping spec fields to RFC 7591 wire names in the request body")
		auth.mu.Lock()
		body := auth.lastBody
		auth.mu.Unlock()
		Expect(body).To(HaveKeyWithValue("client_name", "Example App"))
		Expect(body).To(HaveKeyWithValue("token_endpoint_auth_method", "client_secret_basic"))
		Expect(body).To(HaveKey("redirect_uris"))
		Expect(body).To(HaveKey("grant_types"))

		By("storing the issued credentials in the target Secret")
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "confidential-client-creds", Namespace: namespace,
		}, &secret)).To(Succeed())
		Expect(secret.Data).To(HaveKeyWithValue(secretKeyClientID, []byte("generated-client-id")))
		Expect(secret.Data).To(HaveKeyWithValue(secretKeyClientSecret, []byte("generated-client-secret")))
		Expect(secret.Data).To(HaveKeyWithValue(secretKeyRegAccessToken, []byte("reg-access-token")))
		Expect(secret.Data).To(HaveKey(secretKeyResponse))

		By("owning the Secret for garbage collection")
		Expect(secret.OwnerReferences).To(HaveLen(1))
		Expect(secret.OwnerReferences[0].Kind).To(Equal("DynamicClientRegistration"))

		By("surfacing non-secret fields in status only")
		var got oauthv1alpha1.DynamicClientRegistration
		Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
		Expect(got.Status.ClientID).To(Equal("generated-client-id"))
		Expect(got.Status.RegistrationClientURI).To(ContainSubstring("/register/clients/generated-client-id"))
		Expect(got.Status.ClientIDIssuedAt).NotTo(BeNil())
	})

	It("does not re-register once the credentials Secret exists (idempotency)", func() {
		key := newDCR("idempotent-client", oauthv1alpha1.DynamicClientRegistrationSpec{
			RegistrationEndpoint: auth.registerURL(),
			Client:               oauthv1alpha1.ClientMetadata{ClientName: "Idem"},
		})
		DeferCleanup(func() { deleteAndDrain(ctx, reconciler, key) })

		reconcileUntilReady(key)
		registerCalls, _ := auth.counts()
		Expect(registerCalls).To(Equal(1))

		By("reconciling several more times")
		for range 3 {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred())
		}
		registerCalls, _ = auth.counts()
		Expect(registerCalls).To(Equal(1), "registration endpoint must be called at most once")
	})

	It("handles public clients that receive no client_secret", func() {
		auth.close()
		auth = newFakeAuthServer("", 0) // no client_secret in response
		reconciler.HTTPClient = auth.server.Client()

		key := newDCR("public-client", oauthv1alpha1.DynamicClientRegistrationSpec{
			RegistrationEndpoint: auth.registerURL(),
			Client: oauthv1alpha1.ClientMetadata{
				ClientName:              "Public App",
				TokenEndpointAuthMethod: "none",
			},
		})
		DeferCleanup(func() { deleteAndDrain(ctx, reconciler, key) })

		reconcileUntilReady(key)

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "public-client", Namespace: namespace}, &secret)).To(Succeed())
		Expect(secret.Data).To(HaveKey(secretKeyClientID))
		Expect(secret.Data).NotTo(HaveKey(secretKeyClientSecret))
	})

	It("sends the initial access token when referenced", func() {
		tokenSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "iat", Namespace: namespace},
			Data:       map[string][]byte{"token": []byte("super-secret-iat")},
		}
		Expect(k8sClient.Create(ctx, tokenSecret)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, tokenSecret) })

		key := newDCR("token-client", oauthv1alpha1.DynamicClientRegistrationSpec{
			RegistrationEndpoint:  auth.registerURL(),
			InitialAccessTokenRef: &oauthv1alpha1.SecretKeySelector{Name: "iat", Key: "token"},
			Client:                oauthv1alpha1.ClientMetadata{ClientName: "Token"},
		})
		DeferCleanup(func() { deleteAndDrain(ctx, reconciler, key) })

		reconcileUntilReady(key)

		auth.mu.Lock()
		authHeader := auth.lastAuthHeader
		auth.mu.Unlock()
		Expect(authHeader).To(Equal("Bearer super-secret-iat"))
	})

	It("marks the resource not ready when the endpoint rejects registration", func() {
		rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri"}`))
		}))
		DeferCleanup(rejecting.Close)
		reconciler.HTTPClient = rejecting.Client()

		key := newDCR("rejected-client", oauthv1alpha1.DynamicClientRegistrationSpec{
			RegistrationEndpoint: rejecting.URL,
			Client:               oauthv1alpha1.ClientMetadata{ClientName: "Rejected"},
		})
		DeferCleanup(func() { deleteAndDrain(ctx, reconciler, key) })

		// First pass adds the finalizer; second performs (and fails) registration.
		_, _ = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).To(HaveOccurred())

		var got oauthv1alpha1.DynamicClientRegistration
		Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
		cond := meta.FindStatusCondition(got.Status.Conditions, conditionReady)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("RegistrationRejected"))
	})

	It("aborts the registration request when the context deadline passes", func() {
		// The handler parks until either the client disconnects or cleanup
		// releases it; the explicit channel guarantees Close never wedges if the
		// server does not observe the client's cancellation.
		release := make(chan struct{})
		slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		DeferCleanup(func() { close(release); slow.Close() })
		reconciler.HTTPClient = slow.Client()

		deadlineCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		_, _, err := reconciler.register(deadlineCtx, slow.URL, "", []byte("{}"))
		Expect(err).To(HaveOccurred())
		Expect(deadlineCtx.Err()).To(Equal(context.DeadlineExceeded))
	})

	It("best-effort deletes the upstream registration on teardown", func() {
		key := newDCR("deleted-client", oauthv1alpha1.DynamicClientRegistrationSpec{
			RegistrationEndpoint: auth.registerURL(),
			Client:               oauthv1alpha1.ClientMetadata{ClientName: "Deleted"},
		})
		reconcileUntilReady(key)

		Expect(k8sClient.Delete(ctx, &oauthv1alpha1.DynamicClientRegistration{
			ObjectMeta: metav1.ObjectMeta{Name: "deleted-client", Namespace: namespace},
		})).To(Succeed())

		// Drive reconcile until the finalizer is removed and the object is gone.
		Eventually(func(g Gomega) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
			g.Expect(err).NotTo(HaveOccurred())
			var got oauthv1alpha1.DynamicClientRegistration
			g.Expect(errors.IsNotFound(k8sClient.Get(ctx, key, &got))).To(BeTrue())
		}).Should(Succeed())

		_, deleteCalls := auth.counts()
		Expect(deleteCalls).To(Equal(1))
	})
})

// deleteAndDrain deletes a DynamicClientRegistration and reconciles until its
// finalizer is removed, so tests do not leak finalizer-blocked objects.
func deleteAndDrain(ctx context.Context, r *DynamicClientRegistrationReconciler, key types.NamespacedName) {
	GinkgoHelper()
	var got oauthv1alpha1.DynamicClientRegistration
	if err := k8sClient.Get(ctx, key, &got); err != nil {
		return
	}
	_ = k8sClient.Delete(ctx, &got)
	Eventually(func(g Gomega) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		g.Expect(err).NotTo(HaveOccurred())
		var check oauthv1alpha1.DynamicClientRegistration
		g.Expect(errors.IsNotFound(k8sClient.Get(ctx, key, &check))).To(BeTrue())
	}).Should(Succeed())
}
