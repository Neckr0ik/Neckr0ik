/**
 * Azure Secure Blueprint - Variables
 * Author: Giovanni Oliveira
 * Description: Variables for Azure secure infrastructure deployment
 */

# Core Azure Variables
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
  default     = ""
}

variable "client_secret" {
  description = "Service principal client secret"
  type        = string
  default     = ""
  sensitive   = true
}

# Environment Configuration
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
  default     = "secure-app"
}

# Network Configuration
variable "vnet_address_space" {
  description = "Virtual network address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access resources"
  type        = list(string)
  default     = []
}

# Security Configuration
variable "enable_waf" {
  description = "Enable Web Application Firewall"
  type        = bool
  default     = true
}

variable "enable_ddos_protection" {
  description = "Enable DDoS Protection"
  type        = bool
  default     = false
}

variable "enable_private_endpoints" {
  description = "Enable Private Endpoints for services"
  type        = bool
  default     = true
}

variable "enable_security_center" {
  description = "Enable Azure Security Center"
  type        = bool
  default     = true
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable monitoring and logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

# Backup Configuration
variable "enable_backup" {
  description = "Enable backup for resources"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

# Resource SKUs
variable "app_service_sku" {
  description = "SKU for App Service Plan"
  type        = string
  default     = "P1v2"
}

variable "sql_database_sku" {
  description = "SKU for SQL Database"
  type        = string
  default     = "S1"
}

# Tags
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}