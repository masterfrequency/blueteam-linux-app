variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "db_password" {
  description = "Database password"
  sensitive   = true
}
