# Oracle Free Tier Calibration Lab

This Terraform stack creates public OpenClaw calibration nodes on Oracle Cloud
Infrastructure Always Free resources so you can collect black-box captures from
known versions.

The design goal is simple:

- keep the scanner external-first
- use known-version cloud nodes only to generate remote-visible fingerprints
- make the nodes easy to create and destroy

## What It Deploys

- one public VCN and subnet
- a security list with SSH and gateway ingress
- one or more `VM.Standard.A1.Flex` instances
- a bootstrap script that installs Node 22, installs a pinned `openclaw`
  version with `npm`, writes a gateway config, and starts the gateway service

Each node is tagged with its configured version and exposes the default gateway
port unless you override it.

## Why This Shape

Oracle’s Always Free documentation says the `VM.Standard.A1.Flex` shape is
Always Free eligible and that the free allocation is equivalent to `4` OCPUs
and `24` GB of memory in total. That makes three `1 OCPU / 6 GB` nodes a good
fit for a disposable calibration lab.

## Prereqs

- an OCI account with a home region selected
- Terraform 1.6+
- OCI API auth already configured through the OCI CLI config file or standard
  OCI environment variables
- a pinned Ubuntu image OCID for your home region
- an SSH public key

Oracle recommends pinning a region-specific image OCID instead of using a
dynamic image lookup in Terraform because image listings change over time.

## Quick Start

1. Copy the example variable file:

```bash
cp deploy/oracle_free_tier/terraform.tfvars.example deploy/oracle_free_tier/terraform.tfvars
```

2. Edit `terraform.tfvars` with your compartment, availability domain, image
   OCID, and SSH key.

3. Deploy the lab:

```bash
cd deploy/oracle_free_tier
terraform init
terraform apply
```

4. Export per-version scanner targets:

```bash
terraform output -json calibration_nodes | python3 export_targets.py --version 2026.2.13 > lab-targets-2026.2.13.txt
terraform output -json calibration_nodes | python3 export_targets.py --version 2026.2.14 > lab-targets-2026.2.14.txt
```

5. Capture labeled black-box bundles from the deployed nodes:

```bash
python3 -m openclaw_scanner \
  --targets-file deploy/oracle_free_tier/lab-targets-2026.2.13.txt \
  --capture-version 2026.2.13 \
  --capture-output captures/openclaw-2026.2.13.json \
  --format pretty
```

6. Tear the lab down when you are done:

```bash
terraform destroy
```

## Notes

- The cloud-init script writes `~/.openclaw/openclaw.json` with
  `gateway.mode: "local"`, `gateway.bind: "lan"`, and token auth so the node
  exposes the same public surface the external scanner needs to study.
- `gateway_tokens` are available as a sensitive Terraform output.
- Keep ingress CIDRs narrow if you do not need the nodes to be globally
  reachable.
- If OCI returns an out-of-capacity error for A1 Flex, retry another
  availability domain in your home region.
