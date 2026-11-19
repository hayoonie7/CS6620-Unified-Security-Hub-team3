terraform {
  backend "s3" {
    bucket       = "security-hub-tfstate-605031722137"
    key          = "unified-security-hub/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
