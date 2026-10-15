# automating-compute-security-with-AWS-IAM-trust-policy-auditing---eventbridge

A trust policy is an IAM policy attached to an IAM role that defines what or who is allowed to assume the role. EventBridge is a serverless event bus that receives events from AWS services, applications, and SaaS platforms, filters them through rules, and routes them to targets such as Lambda, SQS, SNS, and Step Functions. EventBridge commonly uses IAM roles with trust policies that allow events to assume the role and perform actions on target services. This lab explains how to implement a trust policy on AWS using EventBridge. 

The lab scenario: The Accidental Cross-Account Admin Role
At CloudScale, a DevOps engineer creates a new backend compute management role (Production-Deployer-Role) to allow automated continuous integration tools to update application deployments. However, due to a typo in the trust relationship policy, the engineer accidentally sets the principal to allow any external AWS account ("AWS": "*") to assume the administrative role. This opens a massive backdoor into your compute infrastructure. The task is to build a serverless cloud watcher that detects dangerous trust policies on IAM roles and automatically strips or updates them in real time.

Step 1: Create a Test IAM Role with a Misconfigured Trust Policy
Open the AWS Management Console on the left navigation menu and navigate to IAM > Roles > Create role. Select Custom trust policy and paste this insecure policy (which allows external cross-account assumptions). This is the policy: 

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

<img width="2631" height="1686" alt="image" src="https://github.com/user-attachments/assets/102fca63-3412-4bf8-afc3-64c5b660f726" />

After populating the JSON field, click Next > name the role CloudScale-Vulnerable-Compute-Role > click Create role. As you can see from the image below, there's a warning that the policy is overly permissive before the policy is created, but this is intentional for this lab: 

<img width="2940" height="1038" alt="image" src="https://github.com/user-attachments/assets/d285e26e-46ac-47d7-ae6f-9f9a186fcac5" />

Step 2: Create the Automated Remediation Lambda Function
Here, I'll build a serverless function that listens for security findings on IAM roles and updates the trust policy to lock it down. To do this, I'll do the following: 

Open the Lambda console and click Create an Event function > select Author from scratch and fill in the basic information with the following details: 

<img width="2794" height="1664" alt="image" src="https://github.com/user-attachments/assets/b15d6c9b-9bc2-4086-9f48-34860511320f" />

Click Create function.

In the code editor, paste the following remediation script:

Python
import json
import boto3

iam_client = boto3.client('iam')

def lambda_handler(event, context):
    print("Received Security Finding Event:")
    print(json.dumps(event))
    
    detail = event.get('detail', {})
    resource_type = detail.get('resourceType')
    resource_arn = detail.get('resource')
    
    # Target IAM Roles flagged for public or unsafe external trust
    if resource_type == 'AWS::IAM::Role':
        # Extract role name from ARN (arn:aws:iam::123456789012:role/RoleName)
        role_name = resource_arn.split('/')[-1]
        print(f"[!] Security Alert: Unsafe trust policy detected on IAM Role: {role_name}")
        
        # Enforce a safe, locked-down baseline trust policy (allowing only the current account)
        safe_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(safe_trust_policy)
            )
            print(f"[+] SUCCESS: Remediated trust policy for IAM Role {role_name}")
        except Exception as e:
            print(f"[!] ERROR updating role {role_name}: {str(e)}")
            raise e
            
    return {
        'statusCode': 200,
        'body': json.dumps('IAM remediation executed successfully!')
    }


Before clicking Deploy, ensure that the IAM policy (iam:UpdateAssumeRolePolicy) is attached to your Lambda execution role under the Configuration tab:

<img width="2763" height="1105" alt="image" src="https://github.com/user-attachments/assets/2a2fa86e-c677-4898-b7fb-c58f3fc1dd69" />

Click Deploy

Step 3: Wire the Event Pipeline with Amazon EventBridge
Open the Amazon EventBridge console > click Rule on the left navigation menu > click Create rule > select Advanced builder. Then fill the "Define rule detail" section with the name and description (optional) before clicking Next: 

<img width="2722" height="954" alt="image" src="https://github.com/user-attachments/assets/4e2ce170-c167-413d-8e1d-350249b6b437" />

In the "Build event pattern" section, configure the Event source as AWS Services and the Event type as Access Analyzer Finding before clicking Next:

<img width="3377" height="1725" alt="image" src="https://github.com/user-attachments/assets/0d2e16ac-3f43-4a23-b930-051c1e2a6f20" />

Specify the target resource as IAM-Role-AutoRemediation Lambda function: 

<img width="2825" height="1683" alt="image" src="https://github.com/user-attachments/assets/37548b36-6b6d-4756-ba83-462407943934" />

Then create the rule.

**Step 4: Testing the pipeline**
Once you create the rule, when AWS IAM Access Analyzer evaluates your environment and detects that CloudScale-Vulnerable-Compute-Role allows external entity assumption, it sends an EventBridge event that triggers your Lambda function to overwrite the unsafe trust policy instantly.

To test the policy, navigate to Lambda, click on the Event Function (IAM-Role-AutoRemediation, in this case) > Test > input this command in the Event JSON:

{
  "version": "0",
  "id": "cdc75b9f-1d8f-e14f-8646-8a7155099888",
  "detail-type": "Access Analyzer Finding Created",
  "source": "aws.access-analyzer",
  "account": "123456789012",
  "time": "2026-10-15T21:00:00Z",
  "region": "us-east-1",
  "detail": {
    "resourceType": "AWS::IAM::Role",
    "resource": "arn:aws:iam::123456789012:role/CloudScale-Audit-Test-Role",
    "status": "ACTIVE"
  }
}

Once you click "test," you'll receive this error, suggesting the user isn't authorized to perform the operation: 
<img width="2812" height="1633" alt="image" src="https://github.com/user-attachments/assets/247c25c4-197e-478a-9bae-614f32d9e550" />
<img width="2296" height="524" alt="image" src="https://github.com/user-attachments/assets/ecabd6c0-203c-4866-b146-4e4c541fdb9c" />


