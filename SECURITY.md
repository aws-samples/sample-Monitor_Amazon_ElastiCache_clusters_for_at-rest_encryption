# Security

## Reporting a vulnerability

If you discover a potential security issue in this project, notify AWS/Amazon Security through the [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/). Do not create a public GitHub issue.

## Scope of this sample

This repository is sample code for demonstration and educational purposes. It is not intended for production use without additional security review, testing, and hardening appropriate to your environment.

The control evaluates only **new** Amazon ElastiCache replication groups, created through the `CreateReplicationGroup` API, in the AWS Region where the stack is deployed. It does not evaluate:

- Existing replication groups or clusters
- Standalone clusters created with `CreateCacheCluster`
- Other AWS Regions or AWS accounts
- Any Region where AWS CloudTrail is not recording management events

For continuous evaluation of existing resources, use an AWS Config managed rule such as `elasticache-repl-grp-encrypted-at-rest`.

## Security controls in this sample

- A customer managed AWS Key Management Service (AWS KMS) key with automatic rotation encrypts the Amazon Simple Notification Service (Amazon SNS) topic, the Amazon Simple Queue Service (Amazon SQS) dead-letter queue, the Amazon CloudWatch Logs log group, and the AWS Lambda environment variables.
- Service principals in the key policy are scoped by encryption context to this stack's topic, queue, and log group.
- The Lambda execution role has one customer managed policy. Each statement is scoped to a single resource.
- The SNS topic policy and the SQS queue policy deny requests that do not use TLS.
- Resource policies use `aws:SourceArn` and `aws:SourceAccount` to prevent confused-deputy access.
- The function has reserved concurrency, EventBridge retries, a target dead-letter queue, a function dead-letter queue, and CloudWatch alarms for function errors and dead-letter queue messages.
- The control fails closed. An event without the `atRestEncryptionEnabled` field is reported as non-compliant, and a failed notification raises an error so that it is retried and alarmed.

## Accepted security debt

These trade-offs are intentional for a sample. Review each one before you use this solution in production.

### 1. Lambda function not attached to a VPC

The function reads only the event payload and calls the regional SNS API. It does not access VPC resources. The checkov `CKV_AWS_117`, cfn_nag `W89`, and cfn-guard `LAMBDA_INSIDE_VPC` checks are suppressed in the template with this justification.

If your policy requires VPC attachment, add `VpcConfig` with private subnets, a security group that allows egress only to a `com.amazonaws.<region>.sns` interface VPC endpoint, and the required elastic network interface permissions.

### 2. KMS key administration and usage delegated to the account root

The key policy follows the AWS default pattern of delegating access to IAM in the account, with an explicit action list instead of `kms:*`. In accounts with broad IAM policies, a principal could disable the key or schedule its deletion, which would stop the control.

For production, add a key administrator role parameter and use it as the administration principal. Add a `kms:ViaService` condition (`sns`, `sqs`, and `lambda` in your Region) to the usage statement.

### 3. No DeletionPolicy on the KMS key or log group

This lets the sample be removed cleanly. When the key is deleted, AWS KMS applies a 30-day waiting period by default.

For production, set `DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain` on `rSNSEncryptionKey` and `rLambdaLogGroup`.

## Production hardening recommendations

- Use separate KMS keys for logs and for messaging (SNS and SQS).
- Apply consistent `Purpose`, `Owner`, and `Environment` tags to every resource, for example with `--tags` on `create-stack`.
- Add descriptions to the IAM role and managed policy.
- Sign the Lambda deployment package with AWS Signer, enforce it with an `AWS::Lambda::CodeSigningConfig`, and restrict writes to the artifact bucket to your deployment pipeline.
- Violation emails include the account ID and the IAM ARN of the creator. Send them to a controlled distribution list, or route findings to AWS Security Hub or another encrypted consumer.
- Deploy the stack in every Region you use, for example with AWS CloudFormation StackSets.
