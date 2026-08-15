package revoke

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/0hardik1/taskgrant/internal/store"
)

func newIAMTestWriter(t *testing.T, handler http.HandlerFunc) *IAMPolicyWriter {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	w, err := NewIAMPolicyWriter(IAMWriterOptions{
		EndpointURL: srv.URL,
		Credentials: store.StaticCredentialsProvider{Credentials: store.AWSCredentials{
			AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret",
		}},
	})
	if err != nil {
		t.Fatalf("NewIAMPolicyWriter: %v", err)
	}
	return w
}

func TestIAMPutRolePolicy(t *testing.T) {
	var form url.Values
	var auth string
	w := newIAMTestWriter(t, func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var err error
		form, err = url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse form: %v", err)
		}
		auth = r.Header.Get("Authorization")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`<PutRolePolicyResponse/>`))
	})
	doc := `{"Version":"2012-10-17","Statement":[]}`
	if err := w.PutRolePolicy(context.Background(), "my-role", PolicyName, doc); err != nil {
		t.Fatalf("PutRolePolicy: %v", err)
	}
	if form.Get("Action") != "PutRolePolicy" || form.Get("RoleName") != "my-role" ||
		form.Get("PolicyName") != PolicyName || form.Get("PolicyDocument") != doc {
		t.Fatalf("form: %v", form)
	}
	if !strings.Contains(auth, "/us-east-1/iam/aws4_request") {
		t.Fatalf("authorization: %s", auth)
	}
}

func TestIAMGetRolePolicyDecodesDocument(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"x"}]}`
	encoded := url.QueryEscape(doc)
	w := newIAMTestWriter(t, func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`<GetRolePolicyResponse>
			<GetRolePolicyResult>
				<RoleName>my-role</RoleName>
				<PolicyName>taskgrant-revocations</PolicyName>
				<PolicyDocument>` + encoded + `</PolicyDocument>
			</GetRolePolicyResult>
		</GetRolePolicyResponse>`))
	})
	got, err := w.GetRolePolicy(context.Background(), "my-role", PolicyName)
	if err != nil {
		t.Fatalf("GetRolePolicy: %v", err)
	}
	if got != doc {
		t.Fatalf("document %q, want %q", got, doc)
	}
}

func TestIAMNoSuchEntityMapsToErrNoSuchPolicy(t *testing.T) {
	w := newIAMTestWriter(t, func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
		rw.Write([]byte(`<ErrorResponse>
			<Error><Code>NoSuchEntity</Code><Message>not found</Message></Error>
		</ErrorResponse>`))
	})
	_, err := w.GetRolePolicy(context.Background(), "my-role", PolicyName)
	if !errors.Is(err, ErrNoSuchPolicy) {
		t.Fatalf("err %v, want ErrNoSuchPolicy", err)
	}
	if err := w.DeleteRolePolicy(context.Background(), "my-role", PolicyName); !errors.Is(err, ErrNoSuchPolicy) {
		t.Fatalf("delete err %v, want ErrNoSuchPolicy", err)
	}
}

func TestIAMOtherErrorsSurface(t *testing.T) {
	w := newIAMTestWriter(t, func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusConflict)
		rw.Write([]byte(`<ErrorResponse>
			<Error><Code>LimitExceeded</Code><Message>too big</Message></Error>
		</ErrorResponse>`))
	})
	err := w.PutRolePolicy(context.Background(), "my-role", PolicyName, "{}")
	if err == nil || !strings.Contains(err.Error(), "LimitExceeded") {
		t.Fatalf("err %v, want LimitExceeded detail", err)
	}
}
