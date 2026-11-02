variable "aws_region" {
  description = "AWS operational region"
  type        = string
  default     = "ca-central-1"
}

variable "project_name" {
  description = "Project identifier"
  type        = string
  default     = "drift-sentinel"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for incident broadcasting"
  type        = string
  default     = ""
}
