terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "security_hub" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "security-hub-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.security_hub.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "security-hub-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.security_hub.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "security-hub-private-subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.security_hub.id

  tags = {
    Name = "security-hub-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.security_hub.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "security-hub-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "api" {
  name        = "security-hub-api-sg"
  description = "API instance security group"
  vpc_id      = aws_vpc.security_hub.id

  ingress {
    description = "HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "security-hub-api-sg"
  }
}

output "vpc_id" {
  value = aws_vpc.security_hub.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "private_subnet_id" {
  value = aws_subnet.private.id
}
resource "aws_ecr_repository" "sast" {
  name                 = "security-hub-sast"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "pentest" {
  name                 = "security-hub-pentest"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

output "sast_ecr_url" {
  value = aws_ecr_repository.sast.repository_url
}

output "pentest_ecr_url" {
  value = aws_ecr_repository.pentest.repository_url
}
resource "aws_sns_topic" "security_alerts" {
  name = "security-hub-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}
# CloudWatch alarm for demonstration of scanner failures
resource "aws_cloudwatch_metric_alarm" "scanner_failure" {
  alarm_name          = "security-hub-scanner-failure"
  alarm_description   = "Alerts when a scanner failure is reported"
  namespace           = "SecurityHubDemo"
  metric_name         = "ScannerFailures"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name = "security-hub-scanner-failure"
  }
}
# Private S3 access through a VPC Gateway Endpoint
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.security_hub.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.public.id,
    aws_vpc.security_hub.default_route_table_id
  ]

  tags = {
    Name = "security-hub-s3-endpoint"
  }
}
# Restrictive security group for penetration-testing tasks
resource "aws_security_group" "pentest" {
  name        = "security-hub-pentest-sg"
  description = "Restrict network access for pentest scanner tasks"
  vpc_id      = aws_vpc.security_hub.id

  ingress = []
  egress  = []

  tags = {
    Name = "security-hub-pentest-sg"
  }
}
# Secrets Manager container for application credentials
resource "aws_secretsmanager_secret" "app" {
  name                    = "security-hub-app-secrets"
  description             = "Application secrets for Unified Security Hub"
  recovery_window_in_days = 7

  tags = {
    Name = "security-hub-app-secrets"
  }
}
