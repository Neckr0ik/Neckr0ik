# Azure Secure Blueprint

Comprehensive Azure infrastructure template implementing security best practices, compliance frameworks, and scalable architecture patterns for enterprise workloads.

## Overview

This blueprint provides a production-ready Azure infrastructure foundation with security, compliance, and operational excellence built-in. It implements a multi-tier architecture with proper network segmentation, identity management, and monitoring capabilities.

## Features

- **Multi-Tier Architecture** - Web, application, and data tier separation
- **Network Security** - Virtual network segmentation with NSGs and firewalls
- **Identity Management** - Azure AD integration with RBAC
- **Encryption** - Data protection at rest and in transit
- **Monitoring** - Comprehensive logging and alerting
- **Compliance** - CIS and NIST framework alignment
- **Disaster Recovery** - Backup and recovery procedures

## Architecture

### High-Level Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Azure Front Door                         │
│                 (Global Load Balancer)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Web Tier (DMZ)                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Application Gateway                          │ │
│  │              (WAF + LB)                                 │ │
│  └─────────────────────┬───────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────┐  ┌────▼────┐  ┌─────────────┐             │
│  │   Web App   │  │ Web App │  │   Web App   │             │
│  │ Service 1   │  │Service 2│  │ Service 3   │             │
│  └─────────────┘  └─────────┘  └─────────────┘             │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Application Tier                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    API      │  │  Function   │  │   Logic     │         │
│  │ Management  │  │    Apps     │  │    Apps     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                   Data Tier                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Azure     │  │   Redis     │  │   Storage   │         │
│  │ SQL Database│  │   Cache     │  │   Account   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Required Tools
```bash
# Terraform (version 1.0+)
terraform --version

# Azure CLI (version 2.0+)
az --version

# Git for version control
git --version
```

### Azure Subscription Setup
```bash
# Login to Azure
az login

# Set subscription (if multiple subscriptions)
az account set --subscription "your-subscription-id"

# Verify current subscription
az account show
```

## Quick Start

### 1. Clone and Setup
```bash
# Clone the repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/2-Cloud-Engineering/2.1-Infrastructure-as-Code/azure-secure-blueprint

# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit configuration with your values
nano terraform.tfvars
```

### 2. Deploy Infrastructure
```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan -out=tfplan

# Apply infrastructure
terraform apply tfplan
```

## Configuration

### Core Variables

#### Required Variables
```hcl
variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}
```

### Environment-Specific Configurations

#### Development Environment
```hcl
# environments/dev.tfvars
environment = "dev"
location    = "East US"

# Smaller, cost-optimized resources
app_service_sku = "B1"
sql_database_sku = "Basic"
enable_backup = false
```

#### Production Environment
```hcl
# environments/prod.tfvars
environment = "prod"
location    = "East US"

# Production-grade resources
app_service_sku = "P2v3"
sql_database_sku = "S2"
enable_backup = true
enable_zone_redundancy = true
```

## Security Features

### Network Security
- Virtual network segmentation
- Network security groups
- Web application firewall
- Private endpoints for services

### Identity and Access Management
- Azure Active Directory integration
- Role-based access control (RBAC)
- Managed identities for services
- Just-in-time access

### Data Protection
- Encryption at rest and in transit
- Key Vault for secret management
- Backup and recovery procedures
- Data lifecycle management

## Monitoring and Compliance

### Azure Monitor Configuration
- Log Analytics workspace
- Application Insights
- Diagnostic settings
- Security Center integration

### Compliance Frameworks
- CIS Azure Benchmark
- NIST Cybersecurity Framework
- Azure Security Benchmark
- PCI DSS requirements

## Contributing

See [CONTRIBUTING.md](../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../LICENSE) for details.