"""
AWS Disclaimer.

(c) 2018 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
This AWS Content is provided subject to the terms of the AWS Customer
Agreement available at https://aws.amazon.com/agreement/ or other written
agreement between Customer and Amazon Web Services, Inc.

Security Control: ElastiCache - Encryption at rest
Description:  Checks for encryption at rest being enabled on ElastiCache (Redis)
Services: ElastiCache, EventBridge, Lambda, SNS

Runtime: Python 3.14
Last Modified: 10/11/2025
"""

import json
import logging
import os
from typing import Any, Dict, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError


# Initialize logger with structured logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get('LOGGING_LEVEL', 'INFO').upper())

# Initialize SNS client outside handler for connection reuse
sns_client = None


def get_sns_client(region: str) -> boto3.client:
    """
    Get or create SNS client for the specified region.
    
    Args:
        region: AWS region name
        
    Returns:
        boto3 SNS client
        
    Raises:
        ValueError: If region is invalid
    """
    if not region or not isinstance(region, str):
        raise ValueError("Invalid region parameter")
    
    global sns_client
    if sns_client is None:
        try:
            sns_client = boto3.client('sns', region_name=region)
        except Exception as e:
            logger.error(f"Failed to create SNS client: {str(e)}")
            raise
    return sns_client


def validate_environment_variables() -> str:
    """
    Validate required environment variables.
    
    Returns:
        SNS topic ARN
        
    Raises:
        ValueError: If required environment variables are missing
    """
    topic_arn = os.environ.get('OUTBOUND_TOPIC_ARN')
    if not topic_arn:
        raise ValueError("OUTBOUND_TOPIC_ARN environment variable is required")
    
    # Validate ARN format
    if not isinstance(topic_arn, str) or not topic_arn.startswith('arn:aws'):
        raise ValueError("Invalid SNS topic ARN format")
    
    return topic_arn


def validate_event_structure(event: Dict[str, Any]) -> None:
    """
    Validate the incoming event structure.
    
    Args:
        event: Lambda event payload
        
    Raises:
        ValueError: If event structure is invalid
    """
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")
    
    required_fields = ['detail', 'account']
    for field in required_fields:
        if field not in event:
            raise ValueError(f"Missing required field: {field}")
    
    detail = event.get('detail')
    if not isinstance(detail, dict):
        raise ValueError("detail must be a dictionary")
    
    required_detail_fields = ['responseElements', 'awsRegion', 'userIdentity']
    for field in required_detail_fields:
        if field not in detail:
            raise ValueError(f"Missing required detail field: {field}")
    
    response_elements = detail.get('responseElements')
    if not isinstance(response_elements, dict):
        raise ValueError("responseElements must be a dictionary")


def check_encryption_status(event: Dict[str, Any]) -> Optional[str]:
    """
    Check the at-rest encryption status from the event.
    
    Args:
        event: Lambda event payload
        
    Returns:
        "VIOLATION" if encryption is disabled, None if compliant or not supported
    """
    try:
        response_elements = event['detail']['responseElements']
    except (KeyError, TypeError) as e:
        logger.error(f"Invalid event structure: {str(e)}")
        raise ValueError("Invalid event structure")
    
    # Check if at-rest encryption is supported for this engine version
    if 'atRestEncryptionEnabled' not in response_elements:
        logger.info("At-rest encryption feature not supported for this engine version")
        return None
    
    encryption_enabled = response_elements.get('atRestEncryptionEnabled', False)
    
    if encryption_enabled:
        logger.info("At-rest encryption is enabled - compliant")
        return None
    else:
        logger.warning("At-rest encryption is disabled - violation detected")
        return "VIOLATION"


def create_violation_message(event: Dict[str, Any]) -> str:
    """
    Create a formatted violation message.
    
    Args:
        event: Lambda event payload
        
    Returns:
        Formatted violation message
    """
    try:
        response_elements = event['detail']['responseElements']
        user_identity = event['detail']['userIdentity']
    except (KeyError, TypeError):
        logger.error("Invalid event structure for message creation")
        raise ValueError("Invalid event structure")
    
    # Safely extract replication group ID
    replication_group_id = response_elements.get('replicationGroupId', 'Unknown')
    
    # Safely extract user ARN
    user_arn = user_identity.get('arn', 'Unknown')
    
    message_parts = [
        "Amazon ElastiCache for Redis - Compliance Violation",
        "",
        "VIOLATION: At-rest encryption is not enabled!",
        f"Replication Group ID: {replication_group_id}",
        "",
        f"Created By: {user_arn}",
        f"Account: {event.get('account', 'Unknown')}",
        f"Region: {event['detail'].get('awsRegion', 'Unknown')}",
    ]
    
    return "\n".join(message_parts)


def send_notification(message: str, topic_arn: str, context: Any) -> bool:
    """
    Send violation notification via SNS.
    
    Args:
        message: Notification message
        topic_arn: SNS topic ARN
        context: Lambda context object
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Extract region from topic ARN
        if not isinstance(topic_arn, str):
            logger.error("Topic ARN must be a string")
            return False
        
        arn_parts = topic_arn.split(':')
        if len(arn_parts) < 6:
            logger.error("Invalid topic ARN format")
            return False
        
        region = arn_parts[3]
        if not region:
            logger.error("Region not found in ARN")
            return False
        
        # Add Lambda context information
        full_message = f"{message}\n\nThis notification was generated by Lambda function: {context.invoked_function_arn}"
        
        # Send notification
        client = get_sns_client(region)
        client.publish(
            TopicArn=topic_arn,
            Message=full_message,
            Subject="ElastiCache Encryption Compliance Violation"
        )
        
        logger.info("Violation notification sent successfully")
        return True
        
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending notification: {str(e)}")
        return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function.
    
    Args:
        event: Lambda event payload
        context: Lambda runtime context
        
    Returns:
        Response dictionary with status and message
    """
    try:
        # Log event for debugging (sanitized)
        logger.info("Processing ElastiCache encryption compliance check")
        logger.debug(f"Event keys: {list(event.keys())}")
        
        # Validate environment and event
        topic_arn = validate_environment_variables()
        validate_event_structure(event)
        
        # Check encryption compliance
        violation_status = check_encryption_status(event)
        
        if violation_status == "VIOLATION":
            # Create and send violation notification
            message = create_violation_message(event)
            success = send_notification(message, topic_arn, context)
            
            if success:
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'status': 'violation_reported',
                        'message': 'Encryption violation detected and notification sent'
                    })
                }
            else:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'status': 'error',
                        'message': 'Violation detected but notification failed'
                    })
                }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'status': 'compliant',
                    'message': 'No encryption violations detected'
                })
            }
            
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({
                'status': 'error',
                'message': f'Invalid input: {str(e)}'
            })
        }
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'status': 'error',
                'message': 'Internal server error'
            })
        }
