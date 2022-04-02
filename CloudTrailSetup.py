import json
import time
from pprint import pprint

import boto3
from botocore.exceptions import ClientError

##FS -in real case it's better to build json files from scrakh, in our case you can keep it for now 
policy_trust_document = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
})
cloudtrail_logs_bucket_policy = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "nubo_AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::my_BucketName"
        },
        {
            "Sid": "nubosec_AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my_BucketName/AWSLogs/my_AccountID/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": "arn:aws:cloudtrail:my_region:my_AccountID:trail/my_trailName"
                }
            }
        }
    ]
}"""

cloudtrail_role_policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {

      "Sid": "AWSCloudTrailCreateLogStream2014110",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream"
      ],
      "Resource": [
        "resource_replace"
      ]

    },
    {
      "Sid": "AWSCloudTrailPutLogEvents20141101",
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "resource_replace"
      ]
    }
  ]
}"""


def set_bucket_policies(cloudtrail_policy, bucket_name='yoavs-cloudtrailbucket', trail_name='SampleTrail'):
    """
    Set cloudtrail policies for s3 bucket
    :param cloudtrail_policy:
    :param bucket_name:
    :param trail_name:
    :return:
    """
    # Todo: Check if exists already (nothing happens if it is)
    s3_client = boto3.client("s3")
    ##FS - in case that you would be used json format, any edits will get better look
    cloudtrail_policy = cloudtrail_policy.replace('my_AccountID', account_id)
    cloudtrail_policy = cloudtrail_policy.replace('my_region', s3_client.meta.region_name)
    cloudtrail_policy = cloudtrail_policy.replace('my_BucketName', bucket_name)
    cloudtrail_policy = cloudtrail_policy.replace('my_trailName', trail_name)

    try:
        response = s3_client.put_bucket_policy(
            Bucket=bucket_name, Policy=cloudtrail_policy
        )
        pprint(response) ## FS - always prefer to use logging library 
        # checking bucket status. This should show us s3 bucket has logs policy
    except ClientError as e:
        print('CloudTrail policy failed')
        print(e)
    except Exception as e:
        print(e)


def list_bucket_policies(bucket_name='yoavs-cloudtrailbucket'):
    """
    This function lists all policies attached to s3 bucket.
    :return: None
    """
    s3_client = boto3.client("s3")
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        pprint(response['Policy'])
    except ClientError as e:
        # if you do not have any policy attached to bucket it will throw error
        # An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicyStatus operation:
        # The bucket policy does not exist
        print("No policy attached to this bucket")

## FS - This function has double functinality, which is not recomended 
def get_cloudtrail_logs_policy(pattern="nubosec-cloudtrail-role-policy"):
    """
    Check for log policy. create one if not exist.
    :param pattern:
    :return: Policy ARN
    """
    global cloudtrail_role_policy
    for policy in iam_client.list_policies(Scope="Local")["Policies"]:
        if pattern in policy["PolicyName"]:
            print(f"Found existing policy {policy['Arn']}.")
            return policy["Arn"]
    else:
        print("Policy not found. Creating new one!")
        try:
            flow_logs_policy = iam_client.create_policy(
                PolicyName=pattern,
                PolicyDocument=cloudtrail_role_policy,
                Description="Policy for Cloudtrail Logs & Cloudwatch stream"
            )
            print(f"New policy is created - {flow_logs_policy['Policy']['Arn']}")
            return flow_logs_policy["Policy"]["Arn"]
        except Exception as err:
            print(err)

## FS - function name doesn't match with acuall use, this function returns the first log group desribe argument
def get_flow_log_group(pattern="flow-logs-group"):
    """
    check if the group already exist and use it if existed. But if the group not exist - create a new one.
    :param pattern: name of the group
    :return: 
    """
    log_client = boto3.client("logs")
    # Check if log group exist. Use it.
    for log_group in log_client.describe_log_groups()["logGroups"]:
        if pattern in log_group["logGroupName"]:
            print(
                f"Found existing group {log_group['logGroupName']}")
            return log_group
    return None

## FS - function name doesn't match with acuall use, you create here double functinality
def get_cloudtrail_log_role_arn(log_group_name, pattern="nubosec-cloudtrail-logs"):
    """
    Create a new role if current one missing. Attach Policy when needed.
    :param log_group_name: Needed for the role policy later
    :param pattern:
    :return: the current\new role ARN
    """
    global cloudtrail_role_policy
    for role in iam_client.list_roles()["Roles"]:
        if pattern in role["RoleName"]:
            print(f"Found existing role {role['Arn']}.")
            # get_role_attached_flow_log_policy(role)
            return role["Arn"]
    else:
        print("Role not found. Creating new one!")

        new_role = iam_client.create_role(
            RoleName=pattern,
            AssumeRolePolicyDocument=policy_trust_document,

            # PermissionsBoundary=get_flow_logs_policy()
        )
        print(f"New role is created - {new_role['Role']['Arn']}")
        # get_role_attached_flow_log_policy(new_role['Role'])
        resource_string = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}" \
                          f":log-stream:{account_id}_CloudTrail_{region}*"
        cloudtrail_role_policy = cloudtrail_role_policy.replace("resource_replace", resource_string)
        iam_client.attach_role_policy(
            RoleName="nubosec-cloudtrail-logs",
            PolicyArn=get_cloudtrail_logs_policy()
        )
        return new_role["Role"]["Arn"]


def create_trail_logs():
    cloudwatch_log_group = get_flow_log_group()

    cloudtrail_role_arn = get_cloudtrail_log_role_arn(cloudwatch_log_group['logGroupName'])
    time.sleep(15)
    if cloudwatch_log_group and cloudtrail_role_arn:
        try:
            response = client.create_trail(
                Name='SampleTrail',
                CloudWatchLogsLogGroupArn=cloudwatch_log_group['arn'],
                CloudWatchLogsRoleArn=cloudtrail_role_arn,
                S3BucketName='yoavs-cloudtrailbucket'
            )
            pprint(response)
            print("Created new trail with cloudwatch group")
        except Exception as e:
            pprint(e)
            print("Failed to create trail")
    else:
        print("No group or role")

## FS - Let's talk about diffarent possible structuers 
if __name__ == '__main__':
    iam_client = boto3.client("iam")
    client = boto3.client('cloudtrail')
    region = boto3.Session().region_name
    account_id = boto3.client('sts').get_caller_identity()['Account'] 

    # list_bucket_policies()
    set_bucket_policies(cloudtrail_logs_bucket_policy)
    create_trail_logs()

    print(client.list_trails())
