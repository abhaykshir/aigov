# ML inference + training infrastructure.
# Stub Terraform — values pinned to predictable strings so the scanner tests
# stay deterministic.

resource "aws_sagemaker_model" "fraud_model" {
  name               = "fraud-detection-model"
  execution_role_arn = "arn:aws:iam::123456789012:role/sagemaker-execution"

  primary_container {
    image          = "763104351884.dkr.ecr.us-east-1.amazonaws.com/sagemaker-inference:latest"
    model_data_url = "s3://example-models/fraud-detection/model.tar.gz"
  }
}

resource "aws_sagemaker_endpoint_configuration" "fraud_endpoint_config" {
  name = "fraud-detection-endpoint-config"

  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.fraud_model.name
    initial_instance_count = 1
    instance_type          = "ml.m5.large"
  }
}

resource "aws_sagemaker_endpoint" "fraud_endpoint" {
  name                 = "fraud-detection-endpoint"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.fraud_endpoint_config.name
}
