terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# IAM Role for Sentinel Lambda Function
resource "aws_iam_role" "sentinel_lambda_role" {
  name        = "${var.project_name}-lambda-role-${var.environment}"
  description = "Execution role granting Sentinel permissions to inspect events and execute self-healing rollbacks"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Least-Privilege Remediation Policy
resource "aws_iam_policy" "sentinel_remediation_policy" {
  name        = "${var.project_name}-remediation-policy-${var.environment}"
  description = "Allows revoking illegal ingress rules and enforcing S3 public access blocks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2SecurityGroupRemediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3PublicAccessRemediation"
        Effect = "Allow"
        Action = [
          "s3:PutAccountPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_remediation_policy" {
  role       = aws_iam_role.sentinel_lambda_role.name
  policy_arn = aws_iam_policy.sentinel_remediation_policy.arn
}

# EventBridge Rule matching mutating CloudTrail events
resource "aws_cloudwatch_event_rule" "drift_detection_rule" {
  name        = "${var.project_name}-drift-rule"
  description = "Intercepts manual CloudTrail API calls that violate cloud security baselines"

  event_pattern = jsonencode({
    source = ["aws.ec2", "aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com", "s3.amazonaws.com"]
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "DeletePublicAccessBlock",
        "PutBucketAcl"
      ]
    }
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Dummy Lambda ZIP for Terraform compilation
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_sentinel.zip"

  source {
    content  = "# Lambda entrypoint"
    filename = "handler.py"
  }
}

resource "aws_lambda_function" "sentinel_healer" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-healer-${var.environment}"
  role             = aws_iam_role.sentinel_lambda_role.arn
  handler          = "src.sentinel.handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      ENVIRONMENT       = var.environment
    }
  }

  tags = {
    Environment = var.environment
  }
}

# EventBridge Target linking Rule to Lambda
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.drift_detection_rule.name
  target_id = "SentinelLambdaTarget"
  arn       = aws_lambda_function.sentinel_healer.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sentinel_healer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift_detection_rule.arn
}
