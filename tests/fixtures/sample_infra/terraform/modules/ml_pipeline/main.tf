variable "model_name" {
  description = "Name of the SageMaker model"
  type        = string
}

variable "execution_role_arn" {
  description = "ARN of the IAM role for SageMaker execution"
  type        = string
}

variable "training_data_uri" {
  description = "S3 URI of training data"
  type        = string
}

resource "aws_sagemaker_model" "pipeline_model" {
  name               = var.model_name
  execution_role_arn = var.execution_role_arn

  primary_container {
    image          = "763104351884.dkr.ecr.us-east-1.amazonaws.com/pytorch-training:2.1.0-gpu-py310"
    model_data_url = "s3://acme-models/${var.model_name}/model.tar.gz"
  }
}

resource "aws_sagemaker_training_job" "pipeline_training" {
  name     = "${var.model_name}-training"
  role_arn = var.execution_role_arn

  algorithm_specification {
    training_image      = "763104351884.dkr.ecr.us-east-1.amazonaws.com/pytorch-training:2.1.0-gpu-py310"
    training_input_mode = "File"
  }

  output_data_config {
    s3_output_path = "s3://acme-models/${var.model_name}/"
  }

  resource_config {
    instance_type     = "ml.p3.2xlarge"
    instance_count    = 1
    volume_size_in_gb = 50
  }

  stopping_condition {
    max_runtime_in_seconds = 86400
  }
}
