# Cloud Security Basics (AWS/Azure/GCP)

## Shared responsibility
- **Provider:** physical, hypervisor, managed service patching
- **You:** IAM, data, network config, app security

## AWS quick audit
```bash
# Authorized assessment only
aws sts get-caller-identity
aws iam get-account-password-policy
aws s3api list-buckets
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0
```

## Common misconfigurations
| Issue | Risk | Fix |
|-------|------|-----|
| S3 bucket public read | data leak | Block Public Access |
| SG 0.0.0.0/0 on 22/3389 | brute force | restrict source IPs |
| IAM `*` actions | privilege escalation | least privilege |
| Long-lived access keys | key theft | IAM roles, rotation |
| Metadata IMDSv1 | SSRF → creds | enforce IMDSv2 |

## Azure
- Check `Get-AzRoleAssignment` for Owner at subscription scope
- Review NSG rules allowing RDP from Internet
- Enable Defender for Cloud recommendations

## GCP
- `gcloud projects get-iam-policy PROJECT`
- Check for `allUsers` / `allAuthenticatedUsers` on buckets

## Cloud IR
1. Disable compromised access keys / rotate
2. Review CloudTrail / Activity Log for API calls
3. Snapshot affected instances before termination
4. Check for new IAM users, roles, Lambda functions

## Detection
- GuardDuty, Defender for Cloud, Security Command Center
- Alert on: `ConsoleLogin` without MFA, `CreateAccessKey`, `PutBucketPolicy`
