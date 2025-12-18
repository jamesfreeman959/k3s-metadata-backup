# k3s Backup and Verification Tool

A comprehensive backup and verification tool for k3s Kubernetes clusters with native API access and Bitwarden Secrets Manager integration.

## Features

- **Native Kubernetes API Access** - Uses official Python Kubernetes client (no kubectl subprocess calls)
- **Bitwarden Integration** - Secure secret management via Bitwarden Secrets Manager
- **S3 Backup Support** - Compatible with AWS S3, Backblaze B2, and other S3-compatible providers
- **Automatic Pruning** - Keeps S3 clean by automatically removing old backups
- **Configurable via Environment Variables** - True 12-factor app, no hard-coded values
- **JSON and Text Output** - Machine-readable JSON or human-friendly text formats
- **Comprehensive Verification** - Checks etcd backups, Longhorn volumes, and node tokens

## Quick Start

### Docker

```bash
docker run -e S3_BUCKET=my-backup-bucket \
  -e BWS_SECRET_ID_ACCESS_KEY=uuid \
  -e BWS_SECRET_ID_SECRET_KEY=uuid \
  -e BWS_SECRET_ID_ENDPOINT=uuid \
  -e BWS_SECRET_ID_REGION=uuid \
  -e BWS_SECRET_ID_BUCKET=uuid \
  -v ~/.kube/config:/root/.kube/config:ro \
  YOUR_USERNAME/k3s-backup:latest verify-all
```

### Kubernetes CronJob

See [`examples/kubernetes-cronjob.yaml`](examples/kubernetes-cronjob.yaml) for a complete example.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: k3s-backup-verify-daily
spec:
  schedule: "0 6 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: verify-all
            image: YOUR_USERNAME/k3s-backup:latest
            args: ["verify-all", "--format", "json"]
            envFrom:
            - configMapRef:
                name: k3s-backup-config
```

## Commands

| Command | Description |
|---------|-------------|
| `backup-node-token` | Backup k3s node token to Bitwarden Secrets Manager |
| `check-node-token` | Verify node token exists in Bitwarden |
| `list-pvs` | List all PersistentVolumes and their PVC mappings |
| `backup-pvs` | Backup PV/PVC list to S3 (with auto-pruning) |
| `backup-nodes` | Backup node information to S3 (with auto-pruning) |
| `verify-etcd` | Verify etcd backups in S3 are recent |
| `verify-longhorn` | Verify Longhorn volume backups are current |
| `verify-all` | Run all verification checks |

## Configuration

All configuration is via **environment variables**:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `S3_BUCKET` | S3 bucket name | `my-backup-bucket` |
| `BWS_SECRET_ID_ACCESS_KEY` | Bitwarden secret UUID for S3 access key | `uuid` |
| `BWS_SECRET_ID_SECRET_KEY` | Bitwarden secret UUID for S3 secret key | `uuid` |
| `BWS_SECRET_ID_ENDPOINT` | Bitwarden secret UUID for S3 endpoint | `uuid` |
| `BWS_SECRET_ID_REGION` | Bitwarden secret UUID for S3 region | `uuid` |
| `BWS_SECRET_ID_BUCKET` | Bitwarden secret UUID for S3 bucket (validation) | `uuid` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLUSTER_NAME` | `k3s` | Unique cluster identifier |
| `S3_ETCD_PREFIX` | `k3s-etcd-snapshots/` | S3 prefix for etcd backups |
| `S3_PV_BACKUP_PREFIX` | `pv-backups/` | S3 prefix for PV list backups |
| `S3_NODES_BACKUP_PREFIX` | `nodes-backups/` | S3 prefix for node info backups |
| `ETCD_BACKUP_MAX_AGE_HOURS` | `24` | Max age (hours) for etcd backups |
| `LONGHORN_BACKUP_MAX_AGE_HOURS` | `48` | Max age (hours) for Longhorn backups |
| `RETENTION_PV_BACKUPS` | `30` | Number of PV backups to keep |
| `RETENTION_NODE_BACKUPS` | `30` | Number of node backups to keep |
| `K8S_CONTEXT` | current | Kubernetes context to use |
| `KUBECONFIG_PATH` | `~/.kube/config` | Path to kubeconfig file |
| `EXTERNAL_SECRETS_NAMESPACE` | `external-secrets` | Namespace for Bitwarden secret |
| `LONGHORN_NAMESPACE` | `longhorn-system` | Longhorn namespace |
| `BWS_SECRET_NAME` | `bitwarden-machine-account` | Name of BWS token secret |
| `BWS_PROJECT` | `k3s` | Bitwarden project name |

## Bitwarden Setup

This tool requires **Bitwarden Secrets Manager** to securely store S3 credentials.

### 1. Create Secrets in Bitwarden

Create these secrets in your Bitwarden Secrets Manager project:

- `longhorn-s3-access-key-id` - Your S3 access key
- `longhorn-s3-secret-access-key` - Your S3 secret key
- `longhorn-s3-endpoint` - S3 endpoint (e.g., `s3.us-west-002.backblazeb2.com`)
- `longhorn-s3-region` - S3 region (e.g., `us-west-002`)
- `longhorn-s3-bucket` - S3 bucket name

### 2. Get Secret UUIDs

```bash
bws secret list
```

Note the UUID for each secret (not the secret name).

### 3. Create Kubernetes Secret with BWS Token

```bash
kubectl create secret generic bitwarden-machine-account \
  --from-literal=token=YOUR_BWS_ACCESS_TOKEN \
  -n external-secrets
```

### 4. Configure Environment Variables

Set the `BWS_SECRET_ID_*` environment variables to the UUIDs from step 2.

## S3 Providers

Works with any S3-compatible provider:

### AWS S3

```bash
export BWS_SECRET_ID_ENDPOINT=<uuid for value: s3.amazonaws.com>
export BWS_SECRET_ID_REGION=<uuid for value: us-east-1>
```

### Backblaze B2

```bash
export BWS_SECRET_ID_ENDPOINT=<uuid for value: s3.us-west-002.backblazeb2.com>
export BWS_SECRET_ID_REGION=<uuid for value: us-west-002>
```

### Hetzner Storage Box

```bash
export BWS_SECRET_ID_ENDPOINT=<uuid for value: fsn1.your-objectstorage.com>
export BWS_SECRET_ID_REGION=<uuid for value: fsn1>
```

## Usage Examples

### Verify All Backups

```bash
./k3s-backup.py verify-all
```

**Output:**
```
================================================================================
k3s Cluster Verification Summary
================================================================================

✓ PASS - Node Token
  Node token exists in BWS

✓ PASS - Etcd Backups
  Most recent backup: 2.50 hours ago
  Threshold: 24 hours

✓ PASS - Longhorn Backups
  Total volumes: 12
  Healthy backups: 12

================================================================================
✓ All checks passed!
================================================================================
```

### Backup PV List

```bash
./k3s-backup.py backup-pvs
```

**Output:**
```
✓ PV list backed up to S3
  Location: s3://my-bucket/pv-backups/pv-list-k3sdev-20251209-143045.json
  PVs backed up: 15 (Bound: 14)
  File size: 2048 bytes
  Pruned 5 old backup(s), kept 30
```

### List PersistentVolumes

```bash
./k3s-backup.py list-pvs
```

### JSON Output

All commands support `--format json`:

```bash
./k3s-backup.py verify-all --format json
```

```json
{
  "timestamp": "2025-12-09T18:00:00+00:00",
  "all_passed": true,
  "checks": {
    "node_token": {
      "success": true,
      "exists": true,
      "passed": true
    },
    "etcd_backups": {
      "age_hours": 2.5,
      "within_threshold": true,
      "passed": true
    },
    "longhorn_backups": {
      "total_volumes": 12,
      "backed_up_volumes": 12,
      "passed": true
    }
  }
}
```

## Kubernetes Deployment

### RBAC Requirements

The tool needs these Kubernetes permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k3s-backup-reader
rules:
- apiGroups: [""]
  resources: ["persistentvolumes", "persistentvolumeclaims", "nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["bitwarden-machine-account"]
- apiGroups: ["longhorn.io"]
  resources: ["backupvolumes"]
  verbs: ["get", "list"]
```

See [`examples/kubernetes-cronjob.yaml`](examples/kubernetes-cronjob.yaml) for complete RBAC setup.

### ConfigMap Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: k3s-backup-config
data:
  CLUSTER_NAME: "k3sdev"
  S3_BUCKET: "my-backup-bucket"
  S3_ETCD_PREFIX: "k3s-etcd-snapshots/"
  BWS_SECRET_ID_ACCESS_KEY: "uuid-here"
  BWS_SECRET_ID_SECRET_KEY: "uuid-here"
  BWS_SECRET_ID_ENDPOINT: "uuid-here"
  BWS_SECRET_ID_REGION: "uuid-here"
  BWS_SECRET_ID_BUCKET: "uuid-here"
```

## Development

### Local Setup

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/k3s-backup.git
cd k3s-backup

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export S3_BUCKET=my-bucket
export BWS_SECRET_ID_ACCESS_KEY=uuid
# ... other variables

# Run locally
./k3s-backup.py verify-all
```

### Build Docker Image

```bash
docker build -t k3s-backup:local .
```

### Run Tests

```bash
# Test help output
docker run k3s-backup:local --help

# Test with your cluster (mount kubeconfig)
docker run -v ~/.kube/config:/root/.kube/config:ro \
  -e S3_BUCKET=my-bucket \
  k3s-backup:local verify-all
```

## Automatic Pruning

The `backup-pvs` and `backup-nodes` commands automatically prune old backups:

- Keeps most recent N backups (configurable via `RETENTION_*_BACKUPS`)
- Always keeps at least 1 backup (safety feature)
- Pruning happens AFTER successful upload
- Reports what was pruned in output

**Example:**
```
✓ Node information backed up to S3
  Location: s3://my-bucket/nodes-backups/nodes-k3sdev-20251209-143045.json
  Nodes backed up: 3
  File size: 4.2 KB
  Pruned 5 old backup(s), kept 30
```

## Troubleshooting

### Missing Required Environment Variables

**Error:** `Missing required environment variables: S3_BUCKET, BWS_SECRET_ID_ACCESS_KEY`

**Solution:** Set all required environment variables listed above.

### Failed to Load Kubernetes Configuration

**Error:** `Failed to load Kubernetes configuration`

**Solutions:**
- Verify kubeconfig exists: `ls ~/.kube/config`
- Test with kubectl: `kubectl get nodes`
- Set `KUBECONFIG` environment variable if needed
- Check `K8S_CONTEXT` setting

### Bitwarden Access Errors

**Error:** `Failed to retrieve secret ... from BWS`

**Solutions:**
- Verify BWS token is valid and not expired
- Check secret UUIDs are correct (not names!)
- Ensure BWS token has read access to secrets
- Test with bws CLI: `bws secret get <uuid>`

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues:** https://github.com/YOUR_USERNAME/k3s-backup/issues
- **Documentation:** See this README and [examples/](examples/)
- **Discussions:** https://github.com/YOUR_USERNAME/k3s-backup/discussions

## Acknowledgments

- Built for k3s Kubernetes distribution
- Uses official Kubernetes Python client
- Integrates with Bitwarden Secrets Manager
- Inspired by real disaster recovery testing gaps

---

**Version:** 2.0
**Last Updated:** December 9, 2025
**Python Version:** 3.7+
**Kubernetes Client:** 28.1.0+
