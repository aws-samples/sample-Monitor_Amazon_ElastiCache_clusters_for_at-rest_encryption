# Monitor Amazon ElastiCache clusters for at-rest encryption

A serverless AWS solution that monitors ElastiCache clusters for encryption-at-rest compliance and sends notifications when non-compliant clusters are detected.

## Overview

This solution automatically monitors all ElastiCache clusters in your AWS account and sends SNS notifications when clusters are found without encryption at rest enabled. It uses EventBridge rules to trigger on ElastiCache cluster creation and modification events, ensuring real-time compliance monitoring.

## Architecture

- **AWS Lambda**: Core monitoring logic with encryption compliance checking
- **Amazon EventBridge**: Event-driven triggers for cluster state changes
- **Amazon SNS**: Notification delivery system
- **AWS KMS**: Encryption key management for SNS topics
- **AWS CloudFormation**: Infrastructure as Code deployment

## Files

- `elasticache_encryption_at_rest.yml` - CloudFormation template
- `index.py` - Lambda function source code
- `README.md` - This documentation

## Prerequisites

- AWS CLI configured with appropriate permissions
- AWS account with ElastiCache service access
- Email address for notifications

## Implementation Steps

### 1. Deploy the CloudFormation Stack

```bash
aws cloudformation create-stack \
  --stack-name elasticache-encryption-monitor \
  --template-body file://elasticache_encryption_at_rest.yml \
  --parameters ParameterKey=NotificationEmail,ParameterValue=your-email@example.com \
  --capabilities CAPABILITY_IAM
```

### 2. Verify Deployment

```bash
aws cloudformation describe-stacks \
  --stack-name elasticache-encryption-monitor \
  --query 'Stacks[0].StackStatus'
```

### 3. Confirm SNS Subscription

Check your email and confirm the SNS subscription to receive notifications.

### 4. Test the Solution

Create a test ElastiCache cluster without encryption to verify notifications:

```bash
aws elasticache create-cache-cluster \
  --cache-cluster-id test-cluster \
  --engine redis \
  --cache-node-type cache.t3.micro \
  --num-cache-nodes 1
```

## Configuration Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| NotificationEmail | Email address for compliance notifications | - | Yes |
| LambdaTimeout | Lambda function timeout in seconds | 60 | No |
| LogRetentionDays | CloudWatch log retention period | 14 | No |

## Security Features

### Encryption
- **SNS Topic**: Encrypted using AWS KMS customer-managed key
- **Lambda Environment**: No sensitive data stored
- **CloudWatch Logs**: Encrypted with default AWS encryption

### IAM Permissions
- **Least Privilege**: Lambda has minimal required permissions
- **Resource-Specific**: Permissions scoped to specific resources
- **No Wildcard Actions**: All actions explicitly defined

### Input Validation
- **Event Structure**: Validates EventBridge event format
- **Cluster Details**: Validates ElastiCache cluster properties
- **Error Handling**: Comprehensive exception handling

## Monitoring and Logging

### CloudWatch Metrics
- Lambda invocations, errors, and duration
- SNS message delivery status
- EventBridge rule execution

### CloudWatch Logs
- Lambda execution logs with structured logging
- Error details and stack traces
- Compliance check results

### Alarms (Optional)
Add CloudWatch alarms for:
- Lambda function errors
- SNS delivery failures
- High Lambda duration

## Security Considerations

- KMS encryption for SNS topics
- Least privilege IAM roles
- Input validation and sanitization
- Structured error handling
- No hardcoded credentials

## Assumptions

1. **AWS Region**: Solution deploys in single region
2. **ElastiCache Access**: Account has ElastiCache read permissions
3. **Email Delivery**: SNS can deliver to provided email address
4. **Event Coverage**: EventBridge captures all relevant ElastiCache events
5. **Compliance Definition**: Encryption at rest is the primary compliance requirement

## Troubleshooting

### Common Issues

**Lambda Function Not Triggering**
- Check EventBridge rule is enabled
- Verify Lambda permissions for EventBridge
- Review CloudWatch logs for errors

**No Email Notifications**
- Confirm SNS subscription in email
- Check SNS topic permissions
- Verify email address parameter

**Permission Errors**
- Ensure CloudFormation has IAM permissions
- Check Lambda execution role permissions
- Verify KMS key permissions

### Debug Commands

```bash
# Check Lambda logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/ElastiCacheEncryptionMonitor

# View recent Lambda invocations
aws logs filter-log-events \
  --log-group-name /aws/lambda/ElastiCacheEncryptionMonitor-Function \
  --start-time $(date -d '1 hour ago' +%s)000

# Check SNS topic
aws sns get-topic-attributes --topic-arn <topic-arn>
```


## Contributing

1. Fork the repository
2. Create feature branch
3. Test changes thoroughly
4. Run security scans
5. Submit pull request with detailed description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- Abhishek Agawane (AWS Security Consultant)
