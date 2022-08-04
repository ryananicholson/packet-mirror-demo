# packet-mirror-demo

## Pre-requisites

- GCP account
- Service account created that can:
    - Create compute instances
    - Create compute instance groups
    - Create compute instance templates
    - TODO: Add others
- JSON key file for above service account
    - Environment variable GOOGLE_CLOUD_KEYFILE_JSON set to file path of key file
- Compute Engine enabled (if using new account)
- `variables.tf` file located in this root directory with the following contents:
    ```
    variable "project" {
        type = string
        default = "<YOUR_PROJECT_NAME>"
    }
    
    variable "region" {
        type = string
        default = "<YOUR_REGION>"
    }
    
    variable "zone" {
        type = string
        default = "<YOUR_ZONE>"
    }

    variable "url" {
        type = string
        default = "<YOUR_WEBSERVER_HOST>"
    }

    variable "key" {
    type = string
    default = "<YOUR_PRIVATE_KEY>"
}

    variable "cert" {
        type = string
        default = "<YOUR_CERTIFICATE_CHAIN>"
    }
    ```
- Domain you control (including DNS)
    - You will populate an A record for your webserver host
    - Terraform will output the appropriate URL for the HTTPS load balancer
    - HTTPS will not function until this record is added

## Terraform

### Apply

Once the above requirements are met, it's rather simple to spin up this environment:

```
terraform init
terraform plan
terraform apply -auto-approve
```

This spins up 18 resources in GCP and will take some time to build and install Zeek (\~1hr on an n1-standard-2 instance).

### Destroy

To destroy everything that Terraform previously built, simply run the command below:

```
terraform destroy -auto-approve
```
