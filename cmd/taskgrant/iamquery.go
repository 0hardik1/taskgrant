package main

// iamquery.go is a small signed client for the IAM Query API, used by
// the preflight heuristics and the provision command. The module
// carries no IAM SDK, so the calls are hand-rolled over net/http with
// the SigV4 signer from internal/store, the same pattern
// internal/revoke uses for its policy writer.

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0hardik1/taskgrant/internal/store"
)

// iamQueryAPIVersion is the IAM Query API version.
const iamQueryAPIVersion = "2010-05-08"

// iamClient performs signed IAM Query API calls.
type iamClient struct {
	base   string
	region string
	creds  store.AWSCredentialsProvider
	http   *http.Client
}

// newIAMClient builds a client. endpointURL empty selects the standard
// IAM endpoint; region empty selects us-east-1 (IAM is global).
func newIAMClient(endpointURL, region string) (*iamClient, error) {
	base := endpointURL
	if base == "" {
		base = "https://iam.amazonaws.com"
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("iam endpoint %q is not a valid http(s) URL", base)
	}
	if region == "" {
		region = "us-east-1"
	}
	return &iamClient{
		base:   strings.TrimRight(base, "/"),
		region: region,
		creds:  store.EnvCredentialsProvider{},
		http:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// iamAPIError is a decoded IAM Query API error.
type iamAPIError struct {
	Code    string
	Message string
	Status  int
}

func (e *iamAPIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("iam: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("iam: http status %d", e.Status)
}

// iamErrorCode extracts the IAM error code from err, or "".
func iamErrorCode(err error) string {
	var e *iamAPIError
	if ok := asIAMError(err, &e); ok {
		return e.Code
	}
	return ""
}

func asIAMError(err error, target **iamAPIError) bool {
	for err != nil {
		if e, ok := err.(*iamAPIError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// iamErrorEnvelope is the XML error shape of the Query API.
type iamErrorEnvelope struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// call performs one signed call and decodes the XML response into out
// when out is non-nil.
func (c *iamClient) call(ctx context.Context, action string, params map[string]string, out any) error {
	form := url.Values{
		"Action":  {action},
		"Version": {iamQueryAPIVersion},
	}
	for k, v := range params {
		form.Set(k, v)
	}
	payload := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/", strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("iam %s: %w", action, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	creds, err := c.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("iam %s: credentials: %w", action, err)
	}
	if err := store.SignV4(req, creds, "iam", c.region, store.SHA256Hex(payload), time.Now()); err != nil {
		return fmt.Errorf("iam %s: sign: %w", action, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("iam %s: %w", action, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("iam %s: read response: %w", action, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var env iamErrorEnvelope
		_ = xml.Unmarshal(body, &env)
		return &iamAPIError{Code: env.Error.Code, Message: env.Error.Message, Status: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("iam %s: decode response: %w", action, err)
	}
	return nil
}

// iamRole is the subset of GetRole this CLI reads.
type iamRole struct {
	RoleName                string
	ARN                     string
	PermissionsBoundaryARN  string
	AssumeRolePolicyPresent bool
}

type getRoleResponse struct {
	Result struct {
		Role struct {
			RoleName                 string `xml:"RoleName"`
			Arn                      string `xml:"Arn"`
			AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
			PermissionsBoundary      struct {
				PermissionsBoundaryArn string `xml:"PermissionsBoundaryArn"`
			} `xml:"PermissionsBoundary"`
		} `xml:"Role"`
	} `xml:"GetRoleResult"`
}

// getRole fetches one role.
func (c *iamClient) getRole(ctx context.Context, roleName string) (iamRole, error) {
	var resp getRoleResponse
	if err := c.call(ctx, "GetRole", map[string]string{"RoleName": roleName}, &resp); err != nil {
		return iamRole{}, err
	}
	return iamRole{
		RoleName:                resp.Result.Role.RoleName,
		ARN:                     resp.Result.Role.Arn,
		PermissionsBoundaryARN:  resp.Result.Role.PermissionsBoundary.PermissionsBoundaryArn,
		AssumeRolePolicyPresent: resp.Result.Role.AssumeRolePolicyDocument != "",
	}, nil
}

// attachedPolicy is one attached managed policy.
type attachedPolicy struct {
	Name string
	ARN  string
}

type listAttachedRolePoliciesResponse struct {
	Result struct {
		AttachedPolicies struct {
			Members []struct {
				PolicyName string `xml:"PolicyName"`
				PolicyArn  string `xml:"PolicyArn"`
			} `xml:"member"`
		} `xml:"AttachedPolicies"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListAttachedRolePoliciesResult"`
}

// listAttachedRolePolicies returns the first page of attached managed
// policies (enough for the broad-role heuristic).
func (c *iamClient) listAttachedRolePolicies(ctx context.Context, roleName string) ([]attachedPolicy, error) {
	var resp listAttachedRolePoliciesResponse
	if err := c.call(ctx, "ListAttachedRolePolicies", map[string]string{"RoleName": roleName}, &resp); err != nil {
		return nil, err
	}
	out := make([]attachedPolicy, 0, len(resp.Result.AttachedPolicies.Members))
	for _, m := range resp.Result.AttachedPolicies.Members {
		out = append(out, attachedPolicy{Name: m.PolicyName, ARN: m.PolicyArn})
	}
	return out, nil
}

type createPolicyResponse struct {
	Result struct {
		Policy struct {
			Arn string `xml:"Arn"`
		} `xml:"Policy"`
	} `xml:"CreatePolicyResult"`
}

// createPolicy creates a customer managed policy and returns its ARN.
func (c *iamClient) createPolicy(ctx context.Context, name, path, document, description string) (string, error) {
	params := map[string]string{
		"PolicyName":     name,
		"PolicyDocument": document,
	}
	if path != "" {
		params["Path"] = path
	}
	if description != "" {
		params["Description"] = description
	}
	var resp createPolicyResponse
	if err := c.call(ctx, "CreatePolicy", params, &resp); err != nil {
		return "", err
	}
	return resp.Result.Policy.Arn, nil
}

type getPolicyResponse struct {
	Result struct {
		Policy struct {
			DefaultVersionId string `xml:"DefaultVersionId"`
		} `xml:"Policy"`
	} `xml:"GetPolicyResult"`
}

// getPolicyDefaultVersion returns the default version id of a policy.
func (c *iamClient) getPolicyDefaultVersion(ctx context.Context, policyARN string) (string, error) {
	var resp getPolicyResponse
	if err := c.call(ctx, "GetPolicy", map[string]string{"PolicyArn": policyARN}, &resp); err != nil {
		return "", err
	}
	return resp.Result.Policy.DefaultVersionId, nil
}

type getPolicyVersionResponse struct {
	Result struct {
		PolicyVersion struct {
			Document string `xml:"Document"`
		} `xml:"PolicyVersion"`
	} `xml:"GetPolicyVersionResult"`
}

// getPolicyVersionDocument returns the decoded JSON document of one
// policy version.
func (c *iamClient) getPolicyVersionDocument(ctx context.Context, policyARN, versionID string) (string, error) {
	var resp getPolicyVersionResponse
	err := c.call(ctx, "GetPolicyVersion", map[string]string{
		"PolicyArn": policyARN,
		"VersionId": versionID,
	}, &resp)
	if err != nil {
		return "", err
	}
	doc, err := url.QueryUnescape(resp.Result.PolicyVersion.Document)
	if err != nil {
		return "", fmt.Errorf("iam GetPolicyVersion: document decode: %w", err)
	}
	return doc, nil
}

// createPolicyVersion writes a new default version.
func (c *iamClient) createPolicyVersion(ctx context.Context, policyARN, document string) error {
	return c.call(ctx, "CreatePolicyVersion", map[string]string{
		"PolicyArn":      policyARN,
		"PolicyDocument": document,
		"SetAsDefault":   "true",
	}, nil)
}

type listPolicyVersionsResponse struct {
	Result struct {
		Versions struct {
			Members []struct {
				VersionId        string `xml:"VersionId"`
				IsDefaultVersion bool   `xml:"IsDefaultVersion"`
			} `xml:"member"`
		} `xml:"Versions"`
	} `xml:"ListPolicyVersionsResult"`
}

// deleteOldestNonDefaultVersion frees a version slot when the 5-version
// ceiling blocks CreatePolicyVersion. Version ids are "v<N>"; the
// lowest N that is not the default goes.
func (c *iamClient) deleteOldestNonDefaultVersion(ctx context.Context, policyARN string) error {
	var resp listPolicyVersionsResponse
	if err := c.call(ctx, "ListPolicyVersions", map[string]string{"PolicyArn": policyARN}, &resp); err != nil {
		return err
	}
	oldest := ""
	oldestN := 0
	for _, v := range resp.Result.Versions.Members {
		if v.IsDefaultVersion {
			continue
		}
		n := 0
		if _, err := fmt.Sscanf(v.VersionId, "v%d", &n); err != nil {
			continue
		}
		if oldest == "" || n < oldestN {
			oldest, oldestN = v.VersionId, n
		}
	}
	if oldest == "" {
		return fmt.Errorf("iam: policy %s has no deletable version", policyARN)
	}
	return c.call(ctx, "DeletePolicyVersion", map[string]string{
		"PolicyArn": policyARN,
		"VersionId": oldest,
	}, nil)
}
