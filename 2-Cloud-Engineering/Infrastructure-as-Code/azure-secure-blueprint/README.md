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

### Network Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Virtual Network                          │
│                   (10.0.0.0/16)                            │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Gateway Subnet                             │ │
│  │               (10.0.1.0/24)                            │ │
│  │  ┌─────────────────┐  ┌─────────────────┐             │ │
│  │  │ Application     │  │   VPN Gateway   │             │ │
│  │  │   Gateway       │  │                 │             │ │
│  │  └─────────────────┘  └─────────────────┘             │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Web Subnet                               │ │
│  │               (10.0.2.0/24)                            │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │   Web App   │  │   Web App   │  │   Web App   │     │ │
│  │  │ Service 1   │  │ Service 2   │  │ Service 3   │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Application Subnet                         │ │
│  │               (10.0.3.0/24)                            │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │    API      │  │  Function   │  │   Logic     │     │ │
│  │  │ Management  │  │    Apps     │  │    Apps     │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Data Subnet                              │ │
│  │               (10.0.4.0/24)                            │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │   Azure     │  │   Redis     │  │  Storage    │     │ │
│  │  │ SQL Database│  │   Cache     │  │  Account    │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └─────────────────────────────────────────────────────────┘ │
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

### Service Principal Creation
```bash
# Create service principal for Terraform
az ad sp create-for-rbac --name "terraform-sp" --role="Contributor" --scopes="/subscriptions/your-subscription-id"

# Note the output values:
# - appId (client_id)
# - password (client_secret)
# - tenant (tenant_id)
```

## Quick Start

### 1. Clone and Setup
```bash
# Clone the repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/2-Cloud-Engineering/Infrastructure-as-Code/azure-secure-blueprint

# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit configuration with your values
nano terraform.tfvars
```

### 2. Configure Variables
```hcl
# terraform.tfvars
subscription_id = "your-azure-subscription-id"
tenant_id      = "your-azure-tenant-id"
client_id      = "your-service-principal-client-id"
client_secret  = "your-service-principal-secret"

# Environment configuration
environment = "dev"  # dev, staging, prod
location    = "East US"
project     = "secure-app"

# Network configuration
vnet_address_space = ["10.0.0.0/16"]
enable_ddos_protection = false  # Set to true for production

# Security configuration
enable_waf = true
enable_backup = true
backup_retention_days = 30

# Monitoring configuration
enable_monitoring = true
log_retention_days = 90

# Tags
tags = {
  Environment = "dev"
  Project     = "secure-app"
  Owner       = "security-team"
  CostCenter  = "IT"
}
```

### 3. Deploy Infrastructure
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

### 4. Verify Deployment
```bash
# Check resource group
az group show --name "rg-secure-app-dev-eastus"

# List created resources
az resource list --resource-group "rg-secure-app-dev-eastus" --output table

# Test web application
curl https://your-app-gateway-ip
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

variable "client_id" {
  description = "Service principal client ID"
  type        = string
}

variable "client_secret" {
  description = "Service principal client secret"
  type        = string
  sensitive   = true
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

variable "project" {
  description = "Project name for resource naming"
  type        = string
}
```

#### Network Configuration
```hcl
variable "vnet_address_space" {
  description = "Virtual network address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_config" {
  description = "Subnet configuration"
  type = map(object({
    address_prefixes = list(string)
    service_endpoints = list(string)
  }))
  default = {
    gateway = {
      address_prefixes  = ["10.0.1.0/24"]
      service_endpoints = []
    }
    web = {
      address_prefixes  = ["10.0.2.0/24"]
      service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault"]
    }
    app = {
      address_prefixes  = ["10.0.3.0/24"]
      service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Sql"]
    }
    data = {
      address_prefixes  = ["10.0.4.0/24"]
      service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Sql"]
    }
  }
}
```

#### Security Configuration
```hcl
variable "security_config" {
  description = "Security configuration settings"
  type = object({
    enable_waf                = bool
    enable_ddos_protection   = bool
    enable_private_endpoints = bool
    allowed_ip_ranges        = list(string)
    ssl_policy               = string
  })
  default = {
    enable_waf                = true
    enable_ddos_protection   = false
    enable_private_endpoints = true
    allowed_ip_ranges        = ["0.0.0.0/0"]  # Restrict in production
    ssl_policy               = "AppGwSslPolicy20220101S"
  }
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
backup_retention_days = 7

# Relaxed security for development
security_config = {
  enable_waf                = false
  enable_ddos_protection   = false
  enable_private_endpoints = false
  allowed_ip_ranges        = ["0.0.0.0/0"]
  ssl_policy               = "AppGwSslPolicy20220101"
}
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
backup_retention_days = 90

# Enhanced security for production
security_config = {
  enable_waf                = true
  enable_ddos_protection   = true
  enable_private_endpoints = true
  allowed_ip_ranges        = ["203.0.113.0/24", "198.51.100.0/24"]  # Your office IPs
  ssl_policy               = "AppGwSslPolicy20220101S"
}

# High availability configuration
enable_zone_redundancy = true
sql_backup_retention = 35
```

## Security Features

### Network Security

#### Network Security Groups (NSGs)
```hcl
# Web tier NSG rules
resource "azurerm_network_security_rule" "web_inbound_https" {
  name                       = "AllowHTTPS"
  priority                   = 100
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "443"
  source_address_prefix      = "*"
  destination_address_prefix = "*"
  resource_group_name        = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
}

resource "azurerm_network_security_rule" "web_inbound_http" {
  name                       = "AllowHTTP"
  priority                   = 110
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "80"
  source_address_prefix      = "*"
  destination_address_prefix = "*"
  resource_group_name        = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
}

# Application tier NSG rules
resource "azurerm_network_security_rule" "app_inbound_web" {
  name                       = "AllowFromWeb"
  priority                   = 100
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "443"
  source_address_prefix      = var.subnet_config.web.address_prefixes[0]
  destination_address_prefix = "*"
  resource_group_name        = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
}

# Data tier NSG rules
resource "azurerm_network_security_rule" "data_inbound_app" {
  name                       = "AllowFromApp"
  priority                   = 100
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "1433"
  source_address_prefix      = var.subnet_config.app.address_prefixes[0]
  destination_address_prefix = "*"
  resource_group_name        = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.data.name
}
```

#### Web Application Firewall (WAF)
```hcl
resource "azurerm_web_application_firewall_policy" "main" {
  count               = var.security_config.enable_waf ? 1 : 0
  name                = "waf-${var.project}-${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  policy_settings {
    enabled                     = true
    mode                       = "Prevention"
    request_body_check         = true
    file_upload_limit_in_mb    = 100
    max_request_body_size_in_kb = 128
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
    
    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = "0.1"
    }
  }

  custom_rules {
    name      = "RateLimitRule"
    priority  = 1
    rule_type = "RateLimitRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = false
      match_values       = ["0.0.0.0/0"]
    }

    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = 100
  }

  tags = var.tags
}
```

### Identity and Access Management

#### Managed Identity Configuration
```hcl
resource "azurerm_user_assigned_identity" "app_identity" {
  name                = "id-${var.project}-${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = var.tags
}

# Grant Key Vault access to managed identity
resource "azurerm_key_vault_access_policy" "app_identity" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = var.tenant_id
  object_id    = azurerm_user_assigned_identity.app_identity.principal_id

  secret_permissions = [
    "Get",
    "List"
  ]

  certificate_permissions = [
    "Get",
    "List"
  ]
}

# Grant Storage access to managed identity
resource "azurerm_role_assignment" "storage_blob_data_contributor" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app_identity.principal_id
}
```

#### Role-Based Access Control (RBAC)
```hcl
# Security team access
resource "azurerm_role_assignment" "security_team" {
  count                = length(var.security_team_members)
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Security Admin"
  principal_id         = var.security_team_members[count.index]
}

# Development team access
resource "azurerm_role_assignment" "dev_team" {
  count                = length(var.dev_team_members)
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = var.dev_team_members[count.index]
}

# Read-only access for monitoring
resource "azurerm_role_assignment" "monitoring" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.monitoring.principal_id
}
```

### Data Protection

#### Encryption at Rest
```hcl
# Storage Account with encryption
resource "azurerm_storage_account" "main" {
  name                     = "st${var.project}${var.environment}${random_string.storage_suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = var.environment == "prod" ? "GRS" : "LRS"
  min_tls_version         = "TLS1_2"
  
  # Enable encryption
  encryption {
    services {
      file {
        enabled = true
      }
      blob {
        enabled = true
      }
    }
    source = "Microsoft.Storage"
  }

  # Network access restrictions
  network_rules {
    default_action             = "Deny"
    virtual_network_subnet_ids = [
      azurerm_subnet.web.id,
      azurerm_subnet.app.id,
      azurerm_subnet.data.id
    ]
    ip_rules = var.security_config.allowed_ip_ranges
  }

  tags = var.tags
}

# SQL Database with Transparent Data Encryption
resource "azurerm_mssql_database" "main" {
  name           = "sqldb-${var.project}-${var.environment}"
  server_id      = azurerm_mssql_server.main.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  license_type   = "LicenseIncluded"
  sku_name       = var.sql_database_sku
  zone_redundant = var.environment == "prod" ? true : false

  # Enable Transparent Data Encryption
  transparent_data_encryption_enabled = true

  tags = var.tags
}
```

#### Key Vault Integration
```hcl
resource "azurerm_key_vault" "main" {
  name                = "kv-${var.project}-${var.environment}-${random_string.keyvault_suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  # Security settings
  enabled_for_disk_encryption     = true
  enabled_for_deployment          = false
  enabled_for_template_deployment = false
  purge_protection_enabled        = var.environment == "prod" ? true : false
  soft_delete_retention_days      = 90

  # Network access restrictions
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    virtual_network_subnet_ids = [
      azurerm_subnet.web.id,
      azurerm_subnet.app.id,
      azurerm_subnet.data.id
    ]
    ip_rules = var.security_config.allowed_ip_ranges
  }

  tags = var.tags
}

# Store database connection string
resource "azurerm_key_vault_secret" "db_connection_string" {
  name         = "database-connection-string"
  value        = "Server=tcp:${azurerm_mssql_server.main.fully_qualified_domain_name},1433;Initial Catalog=${azurerm_mssql_database.main.name};Persist Security Info=False;User ID=${azurerm_mssql_server.main.administrator_login};Password=${random_password.sql_admin.result};MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_key_vault_access_policy.terraform]
}
```

## Monitoring and Logging

### Azure Monitor Configuration
```hcl
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${var.project}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

# Application Insights
resource "azurerm_application_insights" "main" {
  name                = "appi-${var.project}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = var.tags
}

# Diagnostic settings for Key Vault
resource "azurerm_monitor_diagnostic_setting" "keyvault" {
  name                       = "diag-keyvault"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# Diagnostic settings for SQL Database
resource "azurerm_monitor_diagnostic_setting" "sql_database" {
  name                       = "diag-sqldb"
  target_resource_id         = azurerm_mssql_database.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SQLInsights"
  }

  enabled_log {
    category = "AutomaticTuning"
  }

  enabled_log {
    category = "QueryStoreRuntimeStatistics"
  }

  metric {
    category = "Basic"
    enabled  = true
  }
}
```

### Security Monitoring
```hcl
# Security Center (Defender for Cloud)
resource "azurerm_security_center_subscription_pricing" "main" {
  tier          = var.environment == "prod" ? "Standard" : "Free"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  tier          = var.environment == "prod" ? "Standard" : "Free"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = var.environment == "prod" ? "Standard" : "Free"
  resource_type = "StorageAccounts"
}

# Security alerts
resource "azurerm_monitor_metric_alert" "high_cpu" {
  name                = "alert-high-cpu-${var.project}-${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_service_plan.main.id]
  description         = "High CPU usage detected"
  severity            = 2

  criteria {
    metric_namespace = "Microsoft.Web/serverfarms"
    metric_name      = "CpuPercentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  window_size = "PT5M"
  frequency   = "PT1M"

  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }

  tags = var.tags
}

# Action group for notifications
resource "azurerm_monitor_action_group" "main" {
  name                = "ag-${var.project}-${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "secalerts"

  email_receiver {
    name          = "security-team"
    email_address = var.security_team_email
  }

  webhook_receiver {
    name        = "slack-webhook"
    service_uri = var.slack_webhook_url
  }

  tags = var.tags
}
```

## Backup and Disaster Recovery

### Backup Configuration
```hcl
# Recovery Services Vault
resource "azurerm_recovery_services_vault" "main" {
  count               = var.enable_backup ? 1 : 0
  name                = "rsv-${var.project}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Standard"
  soft_delete_enabled = true
  tags                = var.tags
}

# Backup policy for SQL Database
resource "azurerm_mssql_database_extended_auditing_policy" "main" {
  database_id                             = azurerm_mssql_database.main.id
  storage_endpoint                        = azurerm_storage_account.main.primary_blob_endpoint
  storage_account_access_key              = azurerm_storage_account.main.primary_access_key
  storage_account_access_key_is_secondary = false
  retention_in_days                       = var.backup_retention_days
}

# Long-term retention for SQL Database
resource "azurerm_mssql_database_long_term_retention_policy" "main" {
  database_id      = azurerm_mssql_database.main.id
  weekly_retention = "P1W"
  monthly_retention = "P1M"
  yearly_retention = "P1Y"
  week_of_year     = 1
}
```

### Geo-Redundancy
```hcl
# Geo-redundant storage for backups
resource "azurerm_storage_account" "backup" {
  count                    = var.environment == "prod" ? 1 : 0
  name                     = "stbackup${var.project}${var.environment}${random_string.backup_suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = var.backup_location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version         = "TLS1_2"

  tags = var.tags
}

# SQL Database failover group (for production)
resource "azurerm_mssql_failover_group" "main" {
  count       = var.environment == "prod" ? 1 : 0
  name        = "fog-${var.project}-${var.environment}"
  server_id   = azurerm_mssql_server.main.id
  databases   = [azurerm_mssql_database.main.id]

  partner_server {
    id = azurerm_mssql_server.secondary[0].id
  }

  read_write_endpoint_failover_policy {
    mode          = "Automatic"
    grace_minutes = 60
  }

  tags = var.tags
}
```

## Compliance and Governance

### Azure Policy Implementation
```hcl
# Require encryption for storage accounts
resource "azurerm_policy_assignment" "storage_encryption" {
  name                 = "storage-encryption-${var.project}-${var.environment}"
  scope                = azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  description          = "Ensure storage accounts use encryption"
  display_name         = "Storage Account Encryption"

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Require HTTPS for web apps
resource "azurerm_policy_assignment" "https_only" {
  name                 = "https-only-${var.project}-${var.environment}"
  scope                = azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/a4af4a39-4135-47fb-b175-47fbdf85311d"
  description          = "Ensure web apps use HTTPS only"
  display_name         = "Web App HTTPS Only"

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}
```

### Resource Tagging Strategy
```hcl
# Consistent tagging across all resources
locals {
  common_tags = merge(var.tags, {
    Environment     = var.environment
    Project         = var.project
    ManagedBy      = "Terraform"
    CreatedDate    = formatdate("YYYY-MM-DD", timestamp())
    SecurityLevel  = var.environment == "prod" ? "High" : "Medium"
    BackupRequired = var.enable_backup ? "Yes" : "No"
    Compliance     = "CIS-Azure"
  })
}

# Apply tags to all resources
resource "azurerm_resource_group" "main" {
  name     = "rg-${var.project}-${var.environment}-${var.location_short}"
  location = var.location
  tags     = local.common_tags
}
```

## Testing and Validation

### Infrastructure Testing
```bash
#!/bin/bash
# test-infrastructure.sh

echo "Testing Azure Secure Blueprint Infrastructure..."

# Test 1: Verify resource group exists
echo "1. Testing resource group..."
RG_NAME="rg-${PROJECT}-${ENVIRONMENT}-${LOCATION_SHORT}"
if az group show --name "$RG_NAME" &>/dev/null; then
    echo "✅ Resource group exists"
else
    echo "❌ Resource group not found"
    exit 1
fi

# Test 2: Verify network security groups
echo "2. Testing network security groups..."
NSG_WEB="nsg-web-${PROJECT}-${ENVIRONMENT}"
if az network nsg show --resource-group "$RG_NAME" --name "$NSG_WEB" &>/dev/null; then
    echo "✅ Web NSG exists"
else
    echo "❌ Web NSG not found"
    exit 1
fi

# Test 3: Verify Key Vault access
echo "3. Testing Key Vault access..."
KV_NAME="kv-${PROJECT}-${ENVIRONMENT}-${RANDOM_SUFFIX}"
if az keyvault secret list --vault-name "$KV_NAME" &>/dev/null; then
    echo "✅ Key Vault accessible"
else
    echo "❌ Key Vault access failed"
    exit 1
fi

# Test 4: Verify SQL Database connectivity
echo "4. Testing SQL Database..."
SQL_SERVER="sql-${PROJECT}-${ENVIRONMENT}"
if az sql db show --resource-group "$RG_NAME" --server "$SQL_SERVER" --name "sqldb-${PROJECT}-${ENVIRONMENT}" &>/dev/null; then
    echo "✅ SQL Database exists"
else
    echo "❌ SQL Database not found"
    exit 1
fi

# Test 5: Verify Application Gateway
echo "5. Testing Application Gateway..."
AGW_NAME="agw-${PROJECT}-${ENVIRONMENT}"
if az network application-gateway show --resource-group "$RG_NAME" --name "$AGW_NAME" &>/dev/null; then
    echo "✅ Application Gateway exists"
else
    echo "❌ Application Gateway not found"
    exit 1
fi

echo "All tests passed! ✅"
```

### Security Validation
```bash
#!/bin/bash
# validate-security.sh

echo "Validating security configuration..."

# Check encryption settings
echo "1. Validating encryption..."
STORAGE_NAME="st${PROJECT}${ENVIRONMENT}${RANDOM_SUFFIX}"
ENCRYPTION_STATUS=$(az storage account show --name "$STORAGE_NAME" --resource-group "$RG_NAME" --query "encryption.services.blob.enabled" -o tsv)
if [ "$ENCRYPTION_STATUS" = "true" ]; then
    echo "✅ Storage encryption enabled"
else
    echo "❌ Storage encryption not enabled"
fi

# Check network access restrictions
echo "2. Validating network restrictions..."
DEFAULT_ACTION=$(az storage account show --name "$STORAGE_NAME" --resource-group "$RG_NAME" --query "networkRuleSet.defaultAction" -o tsv)
if [ "$DEFAULT_ACTION" = "Deny" ]; then
    echo "✅ Storage network access restricted"
else
    echo "❌ Storage network access not restricted"
fi

# Check Key Vault security
echo "3. Validating Key Vault security..."
KV_NAME="kv-${PROJECT}-${ENVIRONMENT}-${RANDOM_SUFFIX}"
PURGE_PROTECTION=$(az keyvault show --name "$KV_NAME" --query "properties.enablePurgeProtection" -o tsv)
if [ "$PURGE_PROTECTION" = "true" ]; then
    echo "✅ Key Vault purge protection enabled"
else
    echo "⚠️ Key Vault purge protection not enabled (acceptable for dev)"
fi

# Check SQL Database security
echo "4. Validating SQL Database security..."
SQL_SERVER="sql-${PROJECT}-${ENVIRONMENT}"
TDE_STATUS=$(az sql db tde show --resource-group "$RG_NAME" --server "$SQL_SERVER" --database "sqldb-${PROJECT}-${ENVIRONMENT}" --query "status" -o tsv)
if [ "$TDE_STATUS" = "Enabled" ]; then
    echo "✅ SQL Database encryption enabled"
else
    echo "❌ SQL Database encryption not enabled"
fi

echo "Security validation completed!"
```

## Troubleshooting

### Common Issues

#### 1. Terraform Authentication Errors
```bash
# Error: Unable to authenticate to Azure
# Solution: Check service principal credentials
az login --service-principal -u $ARM_CLIENT_ID -p $ARM_CLIENT_SECRET --tenant $ARM_TENANT_ID

# Verify subscription access
az account show
```

#### 2. Resource Naming Conflicts
```bash
# Error: Storage account name already exists
# Solution: Use random suffix for globally unique names
resource "random_string" "storage_suffix" {
  length  = 8
  special = false
  upper   = false
}
```

#### 3. Network Connectivity Issues
```bash
# Error: Cannot connect to SQL Database
# Solution: Check NSG rules and firewall settings
az sql server firewall-rule list --resource-group $RG_NAME --server $SQL_SERVER

# Add your IP to SQL firewall
az sql server firewall-rule create \
  --resource-group $RG_NAME \
  --server $SQL_SERVER \
  --name "AllowMyIP" \
  --start-ip-address $MY_IP \
  --end-ip-address $MY_IP
```

#### 4. Key Vault Access Issues
```bash
# Error: Access denied to Key Vault
# Solution: Check access policies
az keyvault show --name $KV_NAME --query "properties.accessPolicies"

# Add access policy for current user
az keyvault set-policy \
  --name $KV_NAME \
  --upn $(az account show --query user.name -o tsv) \
  --secret-permissions get list set delete
```

### Debugging Commands
```bash
# Check Terraform state
terraform state list
terraform state show azurerm_resource_group.main

# Validate Terraform configuration
terraform validate
terraform plan -detailed-exitcode

# Check Azure resource status
az resource list --resource-group $RG_NAME --output table

# Monitor deployment logs
az monitor activity-log list --resource-group $RG_NAME --max-events 50
```

## Cost Optimization

### Cost Monitoring
```hcl
# Budget alert
resource "azurerm_consumption_budget_resource_group" "main" {
  name              = "budget-${var.project}-${var.environment}"
  resource_group_id = azurerm_resource_group.main.id

  amount     = var.monthly_budget
  time_grain = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  filter {
    dimension {
      name = "ResourceGroupName"
      values = [
        azurerm_resource_group.main.name,
      ]
    }
  }

  notification {
    enabled   = true
    threshold = 80
    operator  = "EqualTo"

    contact_emails = [
      var.billing_contact_email,
    ]
  }

  notification {
    enabled   = true
    threshold = 100
    operator  = "EqualTo"

    contact_emails = [
      var.billing_contact_email,
    ]
  }
}
```

### Resource Optimization
```bash
# Check resource utilization
az monitor metrics list \
  --resource $RESOURCE_ID \
  --metric "Percentage CPU" \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-31T23:59:59Z

# Identify unused resources
az resource list --query "[?tags.Environment=='dev' && tags.LastUsed < '2024-01-01']"

# Right-size recommendations
az advisor recommendation list --category Cost
```

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.

## Support

For issues and questions:
1. Check the [troubleshooting section](#troubleshooting)
2. Review Azure documentation
3. Open an issue in the repository
4. Contact the security team for production issues