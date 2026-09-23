#!/usr/bin/env bash
# Downloads the vendor API descriptions the tests validate requests against.
#
#   test/specs/fetch.sh [DIR]          default DIR=.specs
#   HALLPASS_SPECS_DIR=$PWD/.specs go test ./...
#
# Every file is <name>.spec; internal/integration/itest/spec.go detects the
# format (OpenAPI 3, Swagger 2, Google discovery, botocore). A failed
# download is reported and skipped: the tests then log that validation for
# that API was skipped instead of failing.
set -u
DIR="${1:-.specs}"
mkdir -p "$DIR"
fetch() {
  local name="$1" url="$2"
  if curl -sSfL --retry 3 --max-time 300 "$url" -o "$DIR/$name.spec.tmp"; then
    mv "$DIR/$name.spec.tmp" "$DIR/$name.spec"
    echo "ok   $name"
  else
    rm -f "$DIR/$name.spec.tmp"
    echo "FAIL $name ($url)" >&2
  fi
}
fetch github            https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
fetch gitlab            https://raw.githubusercontent.com/gitlabhq/gitlabhq/master/doc/api/openapi/openapi_v2.yaml
fetch jira              https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json
fetch bitbucket-cloud   https://api.bitbucket.org/swagger.json
fetch confluence-v1     https://developer.atlassian.com/cloud/confluence/swagger.v3.json
fetch confluence-v2     https://developer.atlassian.com/cloud/confluence/openapi-v2.v3.json
fetch slack             https://raw.githubusercontent.com/slackapi/slack-api-specs/master/web-api/slack_web_openapi_v2.json
fetch datadog-v1        https://raw.githubusercontent.com/DataDog/datadog-api-client-go/master/.generator/schemas/v1/openapi.yaml
fetch datadog-v2        https://raw.githubusercontent.com/DataDog/datadog-api-client-go/master/.generator/schemas/v2/openapi.yaml
fetch pagerduty         https://raw.githubusercontent.com/PagerDuty/api-schema/main/reference/REST/openapiv3.json
fetch aws-iam           https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/iam/2010-05-08/service-2.json
fetch aws-sts           https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/sts/2011-06-15/service-2.json
fetch aws-identitystore https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/identitystore/2020-06-15/service-2.json
fetch aws-sso-admin     https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/sso-admin/2020-07-20/service-2.json
fetch msgraph           https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/v1.0/openapi.yaml
fetch google-drive      https://www.googleapis.com/discovery/v1/apis/drive/v3/rest
fetch google-directory  'https://admin.googleapis.com/$discovery/rest?version=directory_v1'
fetch google-calendar   https://www.googleapis.com/discovery/v1/apis/calendar/v3/rest
fetch google-gmail      'https://gmail.googleapis.com/$discovery/rest?version=v1'
fetch zendesk           https://developer.zendesk.com/zendesk/oas.yaml
fetch google-policytroubleshooter 'https://policytroubleshooter.googleapis.com/$discovery/rest?version=v3'
# Jira, from the APIs.guru mirror, when the Atlassian host is unreachable.
[ -f "$DIR/jira.spec" ] || fetch jira https://raw.githubusercontent.com/APIs-guru/openapi-directory/main/APIs/atlassian.com/jira/1001.0.0-SNAPSHOT/openapi.yaml
ls -la "$DIR"
