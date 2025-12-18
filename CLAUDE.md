# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

k3s-metadata-backup is a Python-based metadata backup and verification tool for k3s Kubernetes clusters. It integrates with Bitwarden Secrets Manager for secure credential storage and supports S3-compatible backup storage. The tool uses the official Kubernetes Python client for native API access (no kubectl subprocess calls).

## Core Architecture

### Single-File Design
The entire application is contained in `k3s-metadata-backup.py` - a monolithic Python script structured with clear sections:
- Configuration (lines 46-88): Environment variable loading with defaults
- Helper functions (lines 135-366): BWS token retrieval, Kubernetes API wrappers, S3 client creation
- Command implementations (lines 372-1220): Eight distinct commands as separate functions
- CLI routing (lines 1226-1349): Argparse-based command dispatcher

### Key Dependencies
- **kubernetes**: Native Python client for K8s API operations
- **boto3**: S3 operations for backup storage
- **bws CLI**: Bitwarden Secrets Manager (installed in Docker image, called via subprocess)

### Configuration Philosophy
True 12-factor app - ALL configuration via environment variables. No config files. Required variables:
- `BWS_SECRET_ID_*` (5 UUIDs: access_key, secret_key, endpoint, region, bucket - all S3 credentials stored in Bitwarden)

Optional variables have sensible defaults (see lines 50-76).

### Security Model
1. S3 credentials stored in Bitwarden Secrets Manager (never in environment)
2. BWS access token retrieved from Kubernetes secret (`bitwarden-machine-account`)
3. Tool exchanges BWS token for S3 credentials at runtime
4. Supports both in-cluster (ServiceAccount) and local kubeconfig authentication

## Common Commands

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Set required environment variables
export BWS_SECRET_ID_ACCESS_KEY=uuid
export BWS_SECRET_ID_SECRET_KEY=uuid
export BWS_SECRET_ID_ENDPOINT=uuid
export BWS_SECRET_ID_REGION=uuid
export BWS_SECRET_ID_BUCKET=uuid

# Run commands
./k3s-metadata-backup.py verify-all
./k3s-metadata-backup.py list-pvs
./k3s-metadata-backup.py backup-pvs
```

### Docker Build and Test
```bash
# Build image
docker build -t k3s-metadata-backup:local .

# Test locally (requires kubeconfig)
docker run -v ~/.kube/config:/root/.kube/config:ro \
  -e BWS_SECRET_ID_ACCESS_KEY=uuid \
  -e BWS_SECRET_ID_SECRET_KEY=uuid \
  -e BWS_SECRET_ID_ENDPOINT=uuid \
  -e BWS_SECRET_ID_REGION=uuid \
  -e BWS_SECRET_ID_BUCKET=uuid \
  k3s-metadata-backup:local verify-all
```

### Kubernetes Deployment
See `examples/kubernetes-cronjob.yaml` for full RBAC setup and CronJob configurations.

## Implementation Patterns

### Kubernetes API Access
The tool uses Python Kubernetes client directly (not kubectl). Key patterns:
- `init_k8s_client()` (line 115): Tries kubeconfig first, falls back to in-cluster config
- `client.CoreV1Api()`: For PVs, PVCs, nodes, secrets
- `client.CustomObjectsApi()`: For Longhorn custom resources (BackupVolumes)

Example from `verify_longhorn_backups()` (line 995):
```python
backup_data = get_custom_resources(
    group='longhorn.io',
    version='v1beta2',
    plural='backupvolumes',
    namespace=LONGHORN_NAMESPACE
)
```

### Bitwarden Integration
Two-step credential retrieval:
1. Get BWS access token from K8s secret: `get_bws_token()` (line 151)
2. Call `bws` CLI to fetch S3 credentials: `get_s3_client()` (line 242)

The `bws` CLI is invoked via subprocess with `BWS_ACCESS_TOKEN` in environment.

### S3 Operations with Auto-Pruning
Commands that upload to S3 (`backup-pvs`, `backup-nodes`) automatically prune old backups:
1. Upload new backup file
2. Verify upload succeeded
3. Call `prune_old_backups()` (line 275) to remove old files
4. Keep most recent N backups (configurable via `RETENTION_*_BACKUPS`)

### Output Formatting
All commands support `--format json` or `--format text`:
- JSON mode: Machine-readable for automation/monitoring
- Text mode: Human-friendly with Unicode symbols (✓, ✗, ⚠)

The `verify-all` command (line 1113) runs all checks internally in JSON mode, then formats output for display.

## Data Flow for Backup Commands

1. **backup-pvs** (line 579):
   - Get PVs via K8s API → Extract PV/PVC mappings → Generate JSON → Upload to S3 → Prune old backups

2. **verify-longhorn** (line 962):
   - Get PVs → Get Longhorn BackupVolumes (custom resource) → Join on volume name → Check backup timestamps → Report stale/missing backups

3. **verify-etcd** (line 889):
   - List S3 objects in etcd prefix → Find most recent → Compare timestamp to threshold

## Testing Notes

The tool has no unit tests. Testing is manual:
1. Test help output: `./k3s-metadata-backup.py --help`
2. Test commands individually against real cluster
3. Verify JSON output parsing: `./k3s-metadata-backup.py verify-all --format json | jq`

## Docker Image Details

- Base: `python:3.11-slim`
- Non-root user (UID 1000)
- Includes `bws` CLI (Bitwarden Secrets Manager v0.4.0)
- Entrypoint: `python3 /app/k3s-metadata-backup.py`

## CI/CD

GitHub Actions workflow (`.github/workflows/build-and-push.yml`):
- Triggers: Push to main, version tags (v*.*.*), PRs
- Builds multi-arch Docker image
- Pushes to Docker Hub (on non-PR events)
- Updates Docker Hub README

## Important Gotchas

1. **Secret UUIDs not names**: `BWS_SECRET_ID_*` must be Bitwarden secret UUIDs (get via `bws secret list`), not human-readable names
2. **BWS_PROJECT required for node token backup**: The `backup-node-token` command requires `BWS_PROJECT` to be set to a Bitwarden project UUID (get via `bws project list`), not a project name. This is the only command that needs it.
3. **In-cluster RBAC**: Requires ClusterRole with access to PVs, nodes, and specific secret name
4. **Longhorn dependency**: `verify-longhorn` requires Longhorn CRDs; will fail if Longhorn not installed
5. **Timestamp parsing**: K8s timestamps are RFC3339; tool handles both 'Z' suffix and timezone offsets (line 357)
6. **Pruning safety**: Always keeps at least 1 backup even if retention is 0 (line 313)

## Extending the Tool

To add a new command:
1. Define function following pattern: `def new_command(args)` around line 1111
2. Add argparse subparser in `main()` around line 1309
3. Add to command routing dict around line 1334
4. Follow existing patterns for JSON/text output and error handling
