# Monitor Amazon ElastiCache clusters for at-rest encryption

> **Important**: This solution is sample code for demonstration and educational purposes. It is not intended
> for production use without additional security review, testing, and hardening appropriate to your
> environment. See [SECURITY.md](SECURITY.md) for production hardening recommendations. You are responsible
> for the AWS costs incurred while running this sample.

A serverless sample that sends an email notification when a new Amazon ElastiCache replication group is created without encryption at rest.

## Overview

This solution evaluates **new** Amazon ElastiCache replication groups (`CreateReplicationGroup` API calls) in the AWS Region where it is deployed. When a replication group is created without encryption at rest, it sends a notification through Amazon Simple Notification Service (Amazon SNS).

It does not evaluate existing clusters, standalone clusters created with `CreateCacheCluster`, or other Regions. For existing resources, consider an AWS Config managed rule such as `elasticache-repl-grp-encrypted-at-rest`.

## Architecture

- **AWS CloudTrail**: Records the `CreateReplicationGroup` API call. A trail that records management events in the deployment Region is required.
- **Amazon EventBridge**: A rule matches the CloudTrail event and invokes the function.
- **AWS Lambda**: Reads the event and checks whether encryption at rest is enabled.
- **Amazon SNS**: Delivers the violation notification by email.
- **Amazon Simple Queue Service (Amazon SQS)**: Dead-letter queue for events that could not be processed. Failed event payloads, including the creator's IAM ARN, are kept for 14 days.
- **AWS Key Management Service (AWS KMS)**: A customer managed key encrypts the SNS topic, the SQS queue, the Amazon CloudWatch Logs log group, and the Lambda environment variables.
- **Amazon CloudWatch**: Stores function logs and alarms on function errors and dead-letter queue messages.
- **AWS CloudFormation**: Deploys the resources.

## Files

- `elasticache_encryption_at_rest.yml` - CloudFormation template
- `index.py` - Lambda function source code
- `SECURITY.md` - Scope, accepted trade-offs, and production hardening recommendations

## Prerequisites

- An AWS account and the AWS Command Line Interface (AWS CLI) configured with permissions to create the resources in the template, including named IAM resources
- An AWS CloudTrail trail that records management events in the deployment Region
- A private Amazon Simple Storage Service (Amazon S3) bucket, in the same Region, for the Lambda deployment package
- An email address for notifications

## Implementation Steps

### 1. Package and upload the Lambda code

```bash
zip function.zip index.py
aws s3 cp function.zip s3://<your-artifact-bucket>/functions/elasticache-encryption-monitor.zip
```

### 2. Deploy the CloudFormation stack

```bash
aws cloudformation create-stack \
  --stack-name elasticache-encryption-monitor \
  --template-body file://elasticache_encryption_at_rest.yml \
  --parameters \
    ParameterKey=pLambdaZipBucket,ParameterValue=<your-artifact-bucket> \
    ParameterKey=pLambdaZipKey,ParameterValue=functions/elasticache-encryption-monitor.zip \
    ParameterKey=pNotificationEmail,ParameterValue=<your-email-address> \
  --capabilities CAPABILITY_NAMED_IAM
```

The Lambda function is not attached to a VPC because it only calls the regional Amazon SNS API and does not access VPC resources. If your organization requires VPC attachment, see [SECURITY.md](SECURITY.md).

### 3. Verify the deployment

```bash
aws cloudformation wait stack-create-complete --stack-name elasticache-encryption-monitor
aws cloudformation describe-stacks \
  --stack-name elasticache-encryption-monitor \
  --query 'Stacks[0].StackStatus'
```

### 4. Confirm the SNS subscription

Open the confirmation email from AWS Notifications and choose the confirmation link. You don't receive notifications until the subscription is confirmed.

### 5. Test the solution

Create a small replication group without encryption at rest. A violation email arrives within a few minutes, after CloudTrail delivers the event.

```bash
aws elasticache create-replication-group \
  --replication-group-id test-unencrypted-rg \
  --replication-group-description "Encryption monitor test - delete after use" \
  --engine valkey \
  --cache-node-type cache.t4g.micro \
  --num-cache-clusters 1 \
  --no-at-rest-encryption-enabled \
  --transit-encryption-enabled
```

Delete the test replication group as soon as you receive the email (see [Cleanup](#cleanup)).

## Configuration Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| pLambdaZipBucket | S3 bucket that contains the Lambda deployment package | - | Yes |
| pLambdaZipKey | S3 key of the deployment package (must end in `.zip`) | - | Yes |
| pNotificationEmail | Email address for violation notifications | - | Yes |
| pLoggingLevel | Function logging level (`ERROR`, `WARNING`, `INFO`, `DEBUG`) | INFO | No |
| pReservedConcurrency | Reserved concurrency for the function (1-100) | 10 | No |

The function timeout (60 seconds) and log retention (30 days) are set in the template.

## Security Features

- **Encryption**: A customer managed AWS KMS key with automatic rotation encrypts the SNS topic, SQS queue, CloudWatch Logs log group, and Lambda environment variables. Each service principal in the key policy is scoped to this stack's resource.
- **IAM**: The function role has one customer managed policy, and each statement is scoped to a single resource. The KMS key policy delegates key administration to IAM in the account; see [SECURITY.md](SECURITY.md).
- **Transport**: The SNS topic and SQS queue policies deny requests that don't use TLS.
- **Resource policies**: `aws:SourceArn` and `aws:SourceAccount` conditions limit which resources can invoke the function or write to the topic and queue.
- **Fails closed**: An event without the `atRestEncryptionEnabled` field is reported as non-compliant. If a notification can't be sent, the function raises an error so the event is retried, sent to the dead-letter queue, and alarmed.

## Monitoring and Logging

- **CloudWatch Logs**: Function logs in `/aws/lambda/<stack-name>-LambdaFunction`, kept for 30 days
- **CloudWatch alarms**: `<stack-name>-LambdaErrors` (function errors) and `<stack-name>-DLQMessages` (messages in the dead-letter queue). Both notify the SNS topic.

## Troubleshooting

### Lambda function not triggering

**Symptoms**: No logs in CloudWatch after you create a replication group

**Solutions**:
- Confirm that a CloudTrail trail records management events in this Region: `aws cloudtrail describe-trails`
- Verify the EventBridge rule status: `aws events describe-rule --name elasticache-encryption-monitor-ElastiCacheRule`
- Confirm that you created a replication group (`create-replication-group`). Standalone clusters (`create-cache-cluster`) are not evaluated.

### No email notifications received

**Symptoms**: The function runs successfully but no emails arrive

**Solutions**:
- Confirm the SNS subscription through the email confirmation link
- Check spam or junk folders for SNS emails
- Verify the SNS topic ARN in the function environment variable `OUTBOUND_TOPIC_ARN`

### Lambda function errors

**Error**: `OUTBOUND_TOPIC_ARN environment variable is required`
- Redeploy the stack, and verify the function environment variables in the console

**Error**: `Validation error`
- Failed `CreateReplicationGroup` calls have no response elements and are logged as validation errors. No action is needed.
- Review the CloudWatch logs for event details

**Error**: `Violation detected but SNS notification failed`
- Verify that the function role has `sns:Publish` on the topic and `kms:GenerateDataKey`/`kms:Decrypt` on the stack's KMS key
- Check that the KMS key policy and the SNS topic policy were not modified after deployment

### Debug commands

```bash
# View function logs (function name is <stack-name>-LambdaFunction)
aws logs tail /aws/lambda/elasticache-encryption-monitor-LambdaFunction --since 1h

# Check the EventBridge rule targets
aws events list-targets-by-rule --rule elasticache-encryption-monitor-ElastiCacheRule

# Check the alarms
aws cloudwatch describe-alarms --alarm-name-prefix elasticache-encryption-monitor- \
  --query 'MetricAlarms[].[AlarmName,StateValue]'

# Verify the SNS subscription
aws sns list-subscriptions-by-topic --topic-arn <topic-arn>
```

## Cleanup

```bash
# Delete the test replication group
aws elasticache delete-replication-group --replication-group-id test-unencrypted-rg

# Delete the stack
aws cloudformation delete-stack --stack-name elasticache-encryption-monitor

# Delete the deployment package
aws s3 rm s3://<your-artifact-bucket>/functions/elasticache-encryption-monitor.zip
```

When the stack is deleted, the KMS key enters a 30-day pending-deletion period and is billed until it is deleted.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md). Do not create a public GitHub issue.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

## Authors

- Abhishek Agawane (AWS Security Consultant)
