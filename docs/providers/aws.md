# AWS

## Cluster Types

### GKE

https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/

```json
{
    "Sid": "google",
    "Effect": "Allow",
    "Principal": {
        "Federated": "accounts.google.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
        "StringEquals": {
            "accounts.google.com:oaud": "sts.amazonaws.com",
            "accounts.google.com:email": "test-sa@kubernetes-bifrost.iam.gserviceaccount.com"
        }
    }
}
```
