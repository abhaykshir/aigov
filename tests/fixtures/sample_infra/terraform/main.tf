terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# ── AWS ───────────────────────────────────────────────────────────────────────

resource "aws_sagemaker_endpoint" "inference" {
  name                 = "sentiment-classifier-endpoint"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.inference.name

  tags = {
    Environment = "production"
    Team        = "ml-platform"
  }
}

resource "aws_sagemaker_endpoint_configuration" "inference" {
  name = "sentiment-classifier-config"

  production_variants {
    variant_name           = "primary"
    model_name             = "sentiment-classifier-v2"
    initial_instance_count = 2
    instance_type          = "ml.g4dn.xlarge"
  }
}

resource "aws_bedrock_agent_agent" "research_assistant" {
  agent_name              = "research-assistant"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a research assistant that helps analyze documents."
  agent_resource_role_arn = aws_iam_role.bedrock_agent.arn
}

# ── GCP ───────────────────────────────────────────────────────────────────────

resource "google_vertex_ai_endpoint" "classification" {
  name         = "text-classification-endpoint"
  display_name = "Text Classification"
  location     = "us-central1"
  description  = "Vertex AI endpoint for text classification model"
}

# ── Azure ─────────────────────────────────────────────────────────────────────

resource "azurerm_cognitive_account" "openai" {
  name                = "acme-openai-account"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "OpenAI"
  sku_name            = "S0"

  tags = {
    Environment = "production"
  }
}

# ── Non-AI resource (should NOT be detected) ──────────────────────────────────

resource "aws_s3_bucket" "artifacts" {
  bucket = "acme-ml-artifacts-bucket"

  tags = {
    Environment = "production"
  }
}
