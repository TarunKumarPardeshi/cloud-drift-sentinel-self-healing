output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge drift interception rule"
  value       = aws_cloudwatch_event_rule.drift_detection_rule.arn
}

output "sentinel_lambda_arn" {
  description = "ARN of the Sentinel self-healing Lambda function"
  value       = aws_lambda_function.sentinel_healer.arn
}

output "lambda_execution_role_arn" {
  description = "IAM Role ARN for Lambda execution"
  value       = aws_iam_role.sentinel_lambda_role.arn
}
