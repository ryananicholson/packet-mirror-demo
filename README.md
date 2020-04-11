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