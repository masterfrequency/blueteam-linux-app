terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC
resource "aws_vpc" "blueteam" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "blueteam-vpc"
  }
}

# Security Group
resource "aws_security_group" "blueteam" {
  name        = "blueteam-sg"
  description = "Security group for BlueTeam"
  vpc_id      = aws_vpc.blueteam.id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "blueteam-sg"
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "blueteam" {
  identifier     = "blueteam-db"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.micro"
  
  db_name  = "blueteam"
  username = "blueteam"
  password = var.db_password
  
  allocated_storage = 20
  storage_type      = "gp3"
  
  skip_final_snapshot = true
  
  tags = {
    Name = "blueteam-db"
  }
}

# ElastiCache Redis
resource "aws_elasticache_cluster" "blueteam" {
  cluster_id           = "blueteam-redis"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  engine_version       = "7.0"
  port                 = 6379
  
  tags = {
    Name = "blueteam-redis"
  }
}

# EC2 Instance
resource "aws_instance" "blueteam" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.blueteam.id]
  
  user_data = base64encode(file("${path.module}/user_data.sh"))
  
  tags = {
    Name = "blueteam-instance"
  }
}

# Data source for Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Outputs
output "instance_public_ip" {
  value = aws_instance.blueteam.public_ip
}

output "rds_endpoint" {
  value = aws_db_instance.blueteam.endpoint
}

output "redis_endpoint" {
  value = aws_elasticache_cluster.blueteam.cache_nodes[0].address
}
