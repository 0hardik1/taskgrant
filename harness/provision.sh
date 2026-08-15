#!/usr/bin/env bash
# provision.sh: create every LocalStack resource the taskgrant scenario
# fleet needs. Idempotent: re-running is safe and prints the same
# summary. Never fails on "already exists".
#
# Usage: harness/provision.sh [--skip-lambda]

set -uo pipefail

AWS_BIN="${AWS_BIN:-/opt/homebrew/bin/aws}"
ENDPOINT="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
REGION="us-east-1"
ACCOUNT_ID="000000000000"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$HARNESS_DIR/run"
SKIP_LAMBDA=0
LAMBDA_CREATED=0

for arg in "$@"; do
  case "$arg" in
    --skip-lambda) SKIP_LAMBDA=1 ;;
    *) echo "provision.sh: unknown flag $arg" >&2; exit 2 ;;
  esac
done

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION="$REGION"
export AWS_REGION="$REGION"
export AWS_PAGER=""
unset AWS_PROFILE AWS_SESSION_TOKEN 2>/dev/null || true

mkdir -p "$RUN_DIR"

aws_call() { "$AWS_BIN" --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }

# ok runs an aws call, tolerating "already exists" style failures.
ok() {
  local label="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    echo "  ok    $label"
    return 0
  fi
  case "$out" in
    *AlreadyExists*|*already\ exists*|*BucketAlreadyOwnedByYou*|*ResourceInUseException*|\
    *EntityAlreadyExists*|*ResourceAlreadyExistsException*|*QueueAlreadyExists*|*ResourceConflictException*)
      echo "  exists $label"
      return 0
      ;;
  esac
  echo "  FAIL  $label: $(echo "$out" | tr '\n' ' ' | cut -c1-220)" >&2
  return 1
}

echo "== LocalStack health"
if ! curl -sf "$ENDPOINT/_localstack/health" >/dev/null; then
  echo "provision.sh: LocalStack is not reachable at $ENDPOINT" >&2
  exit 1
fi
echo "  ok    $ENDPOINT reachable"

echo "== S3 buckets"
for b in acme-invoices-prod acme-secret-data acme-ml-artifacts; do
  ok "bucket $b" aws_call s3api create-bucket --bucket "$b"
done

echo "== S3 objects (read scenarios need real keys)"
TMP_OBJ="$RUN_DIR/.provision-object.txt"
printf 'taskgrant harness fixture object\n' > "$TMP_OBJ"
for key in \
  "2026/invoice-0001.json" \
  "2026/invoice-0002.json" \
  "2026/archive/invoice-0003.json" \
  "reports/q3/summary.csv" \
  "reports/q3/detail.csv" \
  "incoming/.keep" ; do
  ok "object s3://acme-invoices-prod/$key" \
    aws_call s3api put-object --bucket acme-invoices-prod --key "$key" --body "$TMP_OBJ"
done
ok "object s3://acme-secret-data/secret.txt" \
  aws_call s3api put-object --bucket acme-secret-data --key "secret.txt" --body "$TMP_OBJ"
rm -f "$TMP_OBJ"

echo "== DynamoDB tables"
for t in invoices invoice-audit; do
  ok "table $t" aws_call dynamodb create-table \
    --table-name "$t" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
done

echo "== SQS queues"
for q in invoice-events invoice-events-dlq; do
  ok "queue $q" aws_call sqs create-queue --queue-name "$q"
done

echo "== CloudWatch log groups"
for lg in "/aws/lambda/invoice-processor" "/ecs/invoice-api"; do
  ok "log group $lg" aws_call logs create-log-group --log-group-name "$lg"
  ok "log stream $lg/harness" aws_call logs create-log-stream \
    --log-group-name "$lg" --log-stream-name "harness"
done

echo "== IAM roles (broker AssumeRole targets)"
TRUST_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::000000000000:root","*"]},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}]}'
for role in taskgrant-default taskgrant-approval-gated taskgrant-short-cap taskgrant-narrow; do
  ok "role $role" aws_call iam create-role \
    --role-name "$role" \
    --assume-role-policy-document "$TRUST_DOC" \
    --max-session-duration 43200
  # Keep the trust policy current even when the role already existed.
  aws_call iam update-assume-role-policy --role-name "$role" \
    --policy-document "$TRUST_DOC" >/dev/null 2>&1
done

echo "== Lambda function (optional: grant minting never touches it)"
if [ "$SKIP_LAMBDA" -eq 1 ]; then
  echo "  skip  lambda invoice-processor (--skip-lambda)"
else
  if aws_call lambda get-function --function-name invoice-processor >/dev/null 2>&1; then
    echo "  exists lambda invoice-processor"
    LAMBDA_CREATED=1
  else
    ZIP="$RUN_DIR/.provision-lambda.zip"
    SRC_DIR="$RUN_DIR/.provision-lambda-src"
    mkdir -p "$SRC_DIR"
    printf 'def handler(event, context):\n    return {"ok": True}\n' > "$SRC_DIR/index.py"
    (cd "$SRC_DIR" && zip -q -r "$ZIP" index.py) 2>/dev/null
    if [ -f "$ZIP" ] && aws_call lambda create-function \
        --function-name invoice-processor \
        --runtime python3.11 \
        --role "arn:aws:iam::$ACCOUNT_ID:role/taskgrant-default" \
        --handler index.handler \
        --timeout 10 \
        --zip-file "fileb://$ZIP" >/dev/null 2>&1; then
      echo "  ok    lambda invoice-processor"
      LAMBDA_CREATED=1
    else
      echo "  skip  lambda invoice-processor (create failed or slow; name-only mapping)"
    fi
    rm -rf "$SRC_DIR" "$ZIP"
  fi
fi

echo
echo "== Summary"
echo "endpoint:        $ENDPOINT"
echo "account/region:  $ACCOUNT_ID / $REGION"
printf 'buckets:         '; aws_call s3api list-buckets --query 'Buckets[].Name' --output text
printf 'objects (prod):  '; aws_call s3api list-objects-v2 --bucket acme-invoices-prod --query 'Contents[].Key' --output text
printf 'tables:          '; aws_call dynamodb list-tables --query 'TableNames' --output text
printf 'queues:          '; aws_call sqs list-queues --query 'QueueUrls' --output text
printf 'log groups:      '; aws_call logs describe-log-groups --query 'logGroups[].logGroupName' --output text
printf 'roles:           '; aws_call iam list-roles --query 'Roles[?starts_with(RoleName, `taskgrant-`)].RoleName' --output text
if [ "$LAMBDA_CREATED" -eq 1 ]; then
  printf 'lambda:          '; aws_call lambda list-functions --query 'Functions[].FunctionName' --output text
else
  echo "lambda:          not created (function_ok is a name-only mapping)"
fi
echo
echo "provision.sh: done"
