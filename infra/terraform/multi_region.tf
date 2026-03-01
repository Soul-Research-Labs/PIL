# ZASEON Multi-Region Deployment
#
# Adds secondary region(s) with:
#   - Aurora Global Database (read replica cluster)
#   - ElastiCache Global Datastore (Redis cross-region)
#   - ECS Fargate cluster (workers + web)
#   - S3 Cross-Region Replication
#   - Route 53 latency-based routing
#   - AWS Global Accelerator for stable anycast endpoints
#
# Usage:
#   Set `enable_multi_region = true` and `secondary_regions` to activate.
#   primary region is inherited from var.aws_region in main.tf.

# ── Variables ────────────────────────────────────────────────────────────────

variable "enable_multi_region" {
  description = "Enable multi-region deployment"
  type        = bool
  default     = false
}

variable "secondary_regions" {
  description = "List of secondary AWS regions"
  type        = list(string)
  default     = ["eu-west-1"]
}

# ── Secondary provider ──────────────────────────────────────────────────────

provider "aws" {
  alias  = "secondary"
  region = length(var.secondary_regions) > 0 ? var.secondary_regions[0] : var.aws_region

  default_tags {
    tags = {
      Project     = "ZASEON"
      Environment = var.environment
      ManagedBy   = "terraform"
      Region      = "secondary"
    }
  }
}

# ── Aurora Global Database ──────────────────────────────────────────────────

resource "aws_rds_global_cluster" "main" {
  count = var.enable_multi_region ? 1 : 0

  global_cluster_identifier = "zaseon-${var.environment}-global"
  source_db_cluster_identifier = aws_rds_cluster.main.arn
  force_destroy             = var.environment != "production"
}

# Secondary VPC in the secondary region
module "vpc_secondary" {
  count   = var.enable_multi_region ? 1 : 0
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  providers = {
    aws = aws.secondary
  }

  name = "zaseon-${var.environment}-secondary"
  cidr = "10.1.0.0/16"

  azs             = [
    "${var.secondary_regions[0]}a",
    "${var.secondary_regions[0]}b",
    "${var.secondary_regions[0]}c",
  ]
  private_subnets = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
  public_subnets  = ["10.1.101.0/24", "10.1.102.0/24", "10.1.103.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment == "staging"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

# Secondary RDS cluster (read replica, promotes on failover)
resource "aws_db_subnet_group" "secondary" {
  count      = var.enable_multi_region ? 1 : 0
  provider   = aws.secondary
  name       = "zaseon-${var.environment}-secondary"
  subnet_ids = module.vpc_secondary[0].private_subnets
}

resource "aws_security_group" "rds_secondary" {
  count       = var.enable_multi_region ? 1 : 0
  provider    = aws.secondary
  name_prefix = "zaseon-rds-sec-"
  vpc_id      = module.vpc_secondary[0].vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_secondary[0].id]
  }
}

resource "aws_rds_cluster" "secondary" {
  count = var.enable_multi_region ? 1 : 0

  provider                    = aws.secondary
  cluster_identifier          = "zaseon-${var.environment}-secondary"
  global_cluster_identifier   = aws_rds_global_cluster.main[0].id
  engine                      = "aurora-postgresql"
  engine_version              = "16.1"
  engine_mode                 = "provisioned"
  db_subnet_group_name        = aws_db_subnet_group.secondary[0].name
  vpc_security_group_ids      = [aws_security_group.rds_secondary[0].id]
  skip_final_snapshot         = var.environment == "staging"

  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = var.environment == "production" ? 8 : 2
  }

  depends_on = [aws_rds_global_cluster.main]
}

resource "aws_rds_cluster_instance" "secondary" {
  count              = var.enable_multi_region ? 1 : 0
  provider           = aws.secondary
  cluster_identifier = aws_rds_cluster.secondary[0].id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.secondary[0].engine
}


# ── ElastiCache Global Datastore ────────────────────────────────────────────

resource "aws_elasticache_global_replication_group" "main" {
  count = var.enable_multi_region ? 1 : 0

  global_replication_group_id_suffix = "zaseon-${var.environment}"
  primary_replication_group_id       = aws_elasticache_replication_group.primary[0].id
}

# Upgrade primary Redis to a replication group (required for global datastore)
resource "aws_elasticache_replication_group" "primary" {
  count = var.enable_multi_region ? 1 : 0

  replication_group_id = "zaseon-${var.environment}-primary"
  description          = "ZASEON primary Redis"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.environment == "production" ? "cache.r7g.large" : "cache.t4g.micro"
  num_cache_clusters   = var.environment == "production" ? 2 : 1
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = [aws_security_group.redis.id]
  automatic_failover_enabled = var.environment == "production"
}

resource "aws_elasticache_subnet_group" "secondary" {
  count      = var.enable_multi_region ? 1 : 0
  provider   = aws.secondary
  name       = "zaseon-${var.environment}-secondary"
  subnet_ids = module.vpc_secondary[0].private_subnets
}

resource "aws_security_group" "redis_secondary" {
  count       = var.enable_multi_region ? 1 : 0
  provider    = aws.secondary
  name_prefix = "zaseon-redis-sec-"
  vpc_id      = module.vpc_secondary[0].vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_secondary[0].id]
  }
}

resource "aws_elasticache_replication_group" "secondary" {
  count = var.enable_multi_region ? 1 : 0

  provider                       = aws.secondary
  replication_group_id           = "zaseon-${var.environment}-secondary"
  description                    = "ZASEON secondary Redis"
  global_replication_group_id    = aws_elasticache_global_replication_group.main[0].global_replication_group_id
  num_cache_clusters             = 1
  subnet_group_name              = aws_elasticache_subnet_group.secondary[0].name
  security_group_ids             = [aws_security_group.redis_secondary[0].id]
}


# ── Secondary ECS Cluster ──────────────────────────────────────────────────

resource "aws_security_group" "ecs_secondary" {
  count       = var.enable_multi_region ? 1 : 0
  provider    = aws.secondary
  name_prefix = "zaseon-ecs-sec-"
  vpc_id      = module.vpc_secondary[0].vpc_id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "secondary" {
  count    = var.enable_multi_region ? 1 : 0
  provider = aws.secondary
  name     = "zaseon-${var.environment}-secondary"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}


# ── S3 Cross-Region Replication ─────────────────────────────────────────────

resource "aws_s3_bucket" "reports_secondary" {
  count    = var.enable_multi_region ? 1 : 0
  provider = aws.secondary
  bucket   = "zaseon-${var.environment}-reports-${var.secondary_regions[0]}"
}

resource "aws_s3_bucket_versioning" "reports_secondary" {
  count    = var.enable_multi_region ? 1 : 0
  provider = aws.secondary
  bucket   = aws_s3_bucket.reports_secondary[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication" {
  count = var.enable_multi_region ? 1 : 0
  name  = "zaseon-${var.environment}-s3-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "replication" {
  count = var.enable_multi_region ? 1 : 0
  name  = "s3-replication"
  role  = aws_iam_role.replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
        ]
        Resource = [aws_s3_bucket.reports.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
        ]
        Resource = ["${aws_s3_bucket.reports.arn}/*"]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
        ]
        Resource = ["${aws_s3_bucket.reports_secondary[0].arn}/*"]
      },
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "reports" {
  count  = var.enable_multi_region ? 1 : 0
  bucket = aws_s3_bucket.reports.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-reports"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.reports_secondary[0].arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [aws_s3_bucket_versioning.reports, aws_s3_bucket_versioning.reports_secondary]
}


# ── Route 53 Latency-Based Routing ──────────────────────────────────────────

resource "aws_route53_zone" "main" {
  count = var.enable_multi_region ? 1 : 0
  name  = var.domain
}

resource "aws_route53_health_check" "primary" {
  count             = var.enable_multi_region ? 1 : 0
  fqdn              = "api-primary.${var.domain}"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/health"
  failure_threshold = 3
  request_interval  = 10
}

resource "aws_route53_health_check" "secondary" {
  count             = var.enable_multi_region ? 1 : 0
  fqdn              = "api-secondary.${var.domain}"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/health"
  failure_threshold = 3
  request_interval  = 10
}

resource "aws_route53_record" "api_primary" {
  count           = var.enable_multi_region ? 1 : 0
  zone_id         = aws_route53_zone.main[0].zone_id
  name            = "api.${var.domain}"
  type            = "A"
  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.primary[0].id

  latency_routing_policy {
    region = var.aws_region
  }

  alias {
    name                   = "api-primary.${var.domain}"
    zone_id                = aws_route53_zone.main[0].zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "api_secondary" {
  count           = var.enable_multi_region ? 1 : 0
  zone_id         = aws_route53_zone.main[0].zone_id
  name            = "api.${var.domain}"
  type            = "A"
  set_identifier  = "secondary"
  health_check_id = aws_route53_health_check.secondary[0].id

  latency_routing_policy {
    region = var.secondary_regions[0]
  }

  alias {
    name                   = "api-secondary.${var.domain}"
    zone_id                = aws_route53_zone.main[0].zone_id
    evaluate_target_health = true
  }
}


# ── Global Accelerator ──────────────────────────────────────────────────────

resource "aws_globalaccelerator_accelerator" "main" {
  count       = var.enable_multi_region ? 1 : 0
  name        = "zaseon-${var.environment}"
  ip_address_type = "IPV4"
  enabled     = true

  attributes {
    flow_logs_enabled = false
  }
}

resource "aws_globalaccelerator_listener" "https" {
  count           = var.enable_multi_region ? 1 : 0
  accelerator_arn = aws_globalaccelerator_accelerator.main[0].id
  protocol        = "TCP"

  port_range {
    from_port = 443
    to_port   = 443
  }
}


# ── Outputs ─────────────────────────────────────────────────────────────────

output "secondary_vpc_id" {
  value = var.enable_multi_region ? module.vpc_secondary[0].vpc_id : ""
}

output "secondary_database_endpoint" {
  value = var.enable_multi_region ? aws_rds_cluster.secondary[0].reader_endpoint : ""
}

output "secondary_ecs_cluster_name" {
  value = var.enable_multi_region ? aws_ecs_cluster.secondary[0].name : ""
}

output "global_accelerator_dns" {
  value = var.enable_multi_region ? aws_globalaccelerator_accelerator.main[0].dns_name : ""
}
