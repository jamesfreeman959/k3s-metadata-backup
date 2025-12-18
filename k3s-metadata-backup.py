#!/usr/bin/env python3
"""
k3s Backup and Verification Tool

This script provides backup operations and verification checks for k3s clusters.
It handles node token backups, PV/PVC listings, and verification of etcd and
Longhorn backups.

Features:
    - Uses Kubernetes Python client for native API access
    - Integrates with Bitwarden Secrets Manager (via bws CLI)
    - Automatic S3 backup pruning to prevent clutter
    - Configurable via environment variables (12-factor app)

Requirements:
    - Kubernetes Python client library (pip install kubernetes)
    - bws (Bitwarden Secrets CLI) installed and accessible
    - boto3 Python library (pip install boto3)
    - Access to the k3s cluster (kubeconfig) and S3 storage
"""

import argparse
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 library not found. Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    print("Error: kubernetes library not found. Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# CONFIGURATION - Set via environment variables
# ============================================================================

# Cluster Identity
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "k3s")

# Kubernetes Configuration
K8S_CONTEXT = os.getenv("K8S_CONTEXT")  # None = use current context
KUBECONFIG_PATH = os.getenv("KUBECONFIG_PATH")  # None = use default
EXTERNAL_SECRETS_NAMESPACE = os.getenv("EXTERNAL_SECRETS_NAMESPACE", "external-secrets")
LONGHORN_NAMESPACE = os.getenv("LONGHORN_NAMESPACE", "longhorn-system")
BWS_SECRET_NAME = os.getenv("BWS_SECRET_NAME", "bitwarden-machine-account")

# Bitwarden Secrets Manager Configuration
BWS_PROJECT = os.getenv("BWS_PROJECT", "k3s")
BWS_NODE_TOKEN_KEY = os.getenv("BWS_NODE_TOKEN_KEY", f"k3s-node-token-{CLUSTER_NAME}")

# S3 Configuration
S3_BUCKET = os.getenv("S3_BUCKET")  # REQUIRED
S3_ETCD_PREFIX = os.getenv("S3_ETCD_PREFIX", "k3s-etcd-snapshots/")
S3_LONGHORN_PREFIX = os.getenv("S3_LONGHORN_PREFIX", "backupstore/")
S3_PV_BACKUP_PREFIX = os.getenv("S3_PV_BACKUP_PREFIX", "pv-backups/")
S3_NODES_BACKUP_PREFIX = os.getenv("S3_NODES_BACKUP_PREFIX", "nodes-backups/")

# Backup Age Thresholds (in hours)
ETCD_BACKUP_MAX_AGE_HOURS = int(os.getenv("ETCD_BACKUP_MAX_AGE_HOURS", "24"))
LONGHORN_BACKUP_MAX_AGE_HOURS = int(os.getenv("LONGHORN_BACKUP_MAX_AGE_HOURS", "48"))

# Backup Retention (number of backups to keep in S3)
RETENTION_PV_BACKUPS = int(os.getenv("RETENTION_PV_BACKUPS", "30"))
RETENTION_NODE_BACKUPS = int(os.getenv("RETENTION_NODE_BACKUPS", "30"))

# k3s Node Token Location
K3S_NODE_TOKEN_PATH = os.getenv("K3S_NODE_TOKEN_PATH", "/var/lib/rancher/k3s/server/node-token")

# BWS Secret UUIDs for S3 credentials - REQUIRED environment variables
BWS_SECRET_IDS = {
    'access_key': os.getenv("BWS_SECRET_ID_ACCESS_KEY"),
    'secret_key': os.getenv("BWS_SECRET_ID_SECRET_KEY"),
    'endpoint': os.getenv("BWS_SECRET_ID_ENDPOINT"),
    'region': os.getenv("BWS_SECRET_ID_REGION"),
    'bucket': os.getenv("BWS_SECRET_ID_BUCKET")
}


# ============================================================================
# Configuration Validation
# ============================================================================

def validate_config():
    """Validate required configuration is set"""
    required = {
        'S3_BUCKET': S3_BUCKET,
        'BWS_SECRET_ID_ACCESS_KEY': BWS_SECRET_IDS['access_key'],
        'BWS_SECRET_ID_SECRET_KEY': BWS_SECRET_IDS['secret_key'],
        'BWS_SECRET_ID_ENDPOINT': BWS_SECRET_IDS['endpoint'],
        'BWS_SECRET_ID_REGION': BWS_SECRET_IDS['region'],
        'BWS_SECRET_ID_BUCKET': BWS_SECRET_IDS['bucket']
    }

    missing = [k for k, v in required.items() if not v]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")


# ============================================================================
# Kubernetes Client Initialization
# ============================================================================

def init_k8s_client():
    """Initialize Kubernetes client configuration"""
    try:
        # Try to load kube config
        if KUBECONFIG_PATH:
            config.load_kube_config(config_file=KUBECONFIG_PATH, context=K8S_CONTEXT)
        else:
            config.load_kube_config(context=K8S_CONTEXT)
    except config.config_exception.ConfigException:
        # If loading kubeconfig fails, try in-cluster config
        try:
            config.load_incluster_config()
        except config.config_exception.ConfigException as e:
            raise Exception(f"Failed to load Kubernetes configuration: {e}")


# ============================================================================
# Helper Functions
# ============================================================================

def run_command(cmd: List[str], capture_output=True, check=True) -> Tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}"


def get_bws_token() -> str:
    """Retrieve BWS access token from Kubernetes secret using Python client"""
    try:
        v1 = client.CoreV1Api()
        secret = v1.read_namespaced_secret(
            name=BWS_SECRET_NAME,
            namespace=EXTERNAL_SECRETS_NAMESPACE
        )

        # Get token from secret data
        if 'token' not in secret.data:
            raise Exception(f"Secret {BWS_SECRET_NAME} does not contain 'token' key")

        # The token is stored as base64 in Kubernetes, need to decode it
        token_data = secret.data['token']

        # The kubernetes client may return bytes or string depending on version
        if isinstance(token_data, bytes):
            # Already decoded from base64, just convert to string
            token = token_data.decode('utf-8')
        else:
            # It's a string, but might still be base64 encoded
            # Try to decode as base64 first
            try:
                token = base64.b64decode(token_data).decode('utf-8')
            except Exception:
                # If base64 decode fails, it's already decoded
                token = token_data

        return token.strip()

    except ApiException as e:
        raise Exception(f"Failed to retrieve BWS token from k8s: {e.reason}")
    except Exception as e:
        raise Exception(f"Failed to retrieve BWS token: {e}")


def k8s_list_to_dict(items: List) -> Dict:
    """Convert Kubernetes API list response to dict format similar to kubectl JSON output"""
    return {
        'apiVersion': 'v1',
        'items': [item.to_dict() for item in items],
        'kind': 'List'
    }


def get_pvs() -> Dict:
    """Get all PersistentVolumes from cluster"""
    try:
        v1 = client.CoreV1Api()
        pv_list = v1.list_persistent_volume()
        return k8s_list_to_dict(pv_list.items)
    except ApiException as e:
        raise Exception(f"Failed to list PersistentVolumes: {e.reason}")


def get_pvcs(namespace: Optional[str] = None) -> Dict:
    """Get PersistentVolumeClaims from cluster"""
    try:
        v1 = client.CoreV1Api()
        if namespace:
            pvc_list = v1.list_namespaced_persistent_volume_claim(namespace=namespace)
        else:
            pvc_list = v1.list_persistent_volume_claim_for_all_namespaces()
        return k8s_list_to_dict(pvc_list.items)
    except ApiException as e:
        raise Exception(f"Failed to list PersistentVolumeClaims: {e.reason}")


def get_custom_resources(group: str, version: str, plural: str, namespace: Optional[str] = None) -> Dict:
    """Get custom resources from cluster"""
    try:
        api = client.CustomObjectsApi()
        if namespace:
            resources = api.list_namespaced_custom_object(
                group=group,
                version=version,
                namespace=namespace,
                plural=plural
            )
        else:
            resources = api.list_cluster_custom_object(
                group=group,
                version=version,
                plural=plural
            )
        return resources
    except ApiException as e:
        raise Exception(f"Failed to list custom resources {plural}: {e.reason}")


def get_s3_client(bws_token: str) -> boto3.client:
    """Create and return an S3 client using credentials from BWS"""
    # Get S3 credentials from BWS
    s3_creds = {}

    for key, secret_id in BWS_SECRET_IDS.items():
        cmd = ["bws", "secret", "get", secret_id, "--output", "json"]
        env = os.environ.copy()
        env['BWS_ACCESS_TOKEN'] = bws_token

        result = subprocess.run(cmd, capture_output=True, text=True, env=env)

        if result.returncode != 0:
            raise Exception(f"Failed to retrieve secret {secret_id} ({key}) from BWS: {result.stderr}")

        try:
            secret_data = json.loads(result.stdout)
            s3_creds[key] = secret_data.get('value', '')
        except json.JSONDecodeError:
            raise Exception(f"Failed to parse BWS response for secret {secret_id} ({key})")

    # Create S3 client
    s3_client = boto3.client(
        's3',
        aws_access_key_id=s3_creds['access_key'],
        aws_secret_access_key=s3_creds['secret_key'],
        endpoint_url=f"https://{s3_creds['endpoint']}",
        region_name=s3_creds['region']
    )

    return s3_client


def prune_old_backups(s3_client: boto3.client, prefix: str, retention_count: int, file_pattern: str) -> Dict:
    """
    Prune old backup files from S3, keeping only the most recent N files.

    Args:
        s3_client: Boto3 S3 client
        prefix: S3 prefix (folder) to search in
        retention_count: Number of most recent backups to keep
        file_pattern: Filename pattern to match (e.g., 'pv-list-', 'nodes-')

    Returns:
        Dict with keys: deleted_count, deleted_files, kept_count, error (if any)
    """
    result = {
        'deleted_count': 0,
        'deleted_files': [],
        'kept_count': 0,
        'error': None
    }

    try:
        # List all objects with the given prefix
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)

        if 'Contents' not in response:
            # No files found - nothing to prune
            return result

        # Filter to only files matching the pattern and sort by modification time (newest first)
        matching_files = [
            obj for obj in response['Contents']
            if file_pattern in obj['Key']
        ]

        # Sort by LastModified descending (newest first)
        matching_files.sort(key=lambda x: x['LastModified'], reverse=True)

        # Ensure we keep at least 1 backup even if retention is 0
        keep_count = max(1, retention_count)

        # Files to keep (most recent N)
        files_to_keep = matching_files[:keep_count]
        result['kept_count'] = len(files_to_keep)

        # Files to delete (everything else)
        files_to_delete = matching_files[keep_count:]

        # Delete old files
        for obj in files_to_delete:
            try:
                s3_client.delete_object(Bucket=S3_BUCKET, Key=obj['Key'])
                result['deleted_files'].append({
                    'key': obj['Key'],
                    'last_modified': obj['LastModified'].isoformat(),
                    'size': obj['Size']
                })
                result['deleted_count'] += 1
            except ClientError as e:
                # Log error but continue deleting other files
                if result['error'] is None:
                    result['error'] = []
                result['error'].append(f"Failed to delete {obj['Key']}: {e}")

        return result

    except ClientError as e:
        result['error'] = f"S3 error during pruning: {e}"
        return result
    except Exception as e:
        result['error'] = f"Unexpected error during pruning: {e}"
        return result


def format_output(data: Any, output_format: str) -> str:
    """Format output as text or JSON"""
    if output_format == 'json':
        return json.dumps(data, indent=2, default=str)
    else:
        # Text format - handled by individual commands
        return data


def parse_k8s_timestamp(timestamp: str) -> datetime:
    """Parse Kubernetes timestamp (RFC3339) to datetime object"""
    try:
        # Handle timestamps with 'Z' suffix
        if timestamp.endswith('Z'):
            timestamp = timestamp[:-1] + '+00:00'
        return datetime.fromisoformat(timestamp)
    except Exception as e:
        raise ValueError(f"Failed to parse timestamp '{timestamp}': {e}")


# ============================================================================
# Command Implementations
# ============================================================================

def backup_node_token(args):
    """Backup k3s node token to Bitwarden Secrets Manager"""
    result = {
        'success': False,
        'message': '',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get BWS token
        bws_token = get_bws_token()

        # Read node token from file
        if not os.path.exists(K3S_NODE_TOKEN_PATH):
            result['message'] = f"Node token file not found: {K3S_NODE_TOKEN_PATH}"
            print(format_output(result, args.format))
            sys.exit(1)

        try:
            with open(K3S_NODE_TOKEN_PATH, 'r') as f:
                node_token = f.read().strip()
        except PermissionError:
            result['message'] = f"Permission denied reading {K3S_NODE_TOKEN_PATH}. Run with sudo?"
            print(format_output(result, args.format))
            sys.exit(1)

        if not node_token:
            result['message'] = "Node token file is empty"
            print(format_output(result, args.format))
            sys.exit(1)

        # Check if secret already exists in BWS
        env = os.environ.copy()
        env['BWS_ACCESS_TOKEN'] = bws_token

        check_cmd = ["bws", "secret", "get", BWS_NODE_TOKEN_KEY, "--output", "json"]
        check_result = subprocess.run(check_cmd, capture_output=True, text=True, env=env)

        if check_result.returncode == 0:
            # Secret exists - update it
            try:
                existing_secret = json.loads(check_result.stdout)
                secret_id = existing_secret['id']

                # Update the secret
                update_cmd = [
                    "bws", "secret", "edit", secret_id,
                    "--value", node_token
                ]
                update_result = subprocess.run(update_cmd, capture_output=True, text=True, env=env)

                if update_result.returncode != 0:
                    result['message'] = f"Failed to update node token in BWS: {update_result.stderr}"
                    print(format_output(result, args.format))
                    sys.exit(1)

                result['success'] = True
                result['message'] = f"Node token updated in BWS (key: {BWS_NODE_TOKEN_KEY})"
                result['action'] = 'updated'

            except json.JSONDecodeError:
                result['message'] = "Failed to parse existing secret data from BWS"
                print(format_output(result, args.format))
                sys.exit(1)
        else:
            # Secret doesn't exist - create it
            create_cmd = [
                "bws", "secret", "create",
                BWS_PROJECT,
                BWS_NODE_TOKEN_KEY,
                node_token,
                "--output", "json"
            ]
            create_result = subprocess.run(create_cmd, capture_output=True, text=True, env=env)

            if create_result.returncode != 0:
                result['message'] = f"Failed to create node token in BWS: {create_result.stderr}"
                print(format_output(result, args.format))
                sys.exit(1)

            result['success'] = True
            result['message'] = f"Node token created in BWS (key: {BWS_NODE_TOKEN_KEY})"
            result['action'] = 'created'

        if args.format == 'json':
            print(format_output(result, args.format))
        else:
            print(f"✓ {result['message']}")

    except Exception as e:
        result['message'] = str(e)
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def check_node_token(args):
    """Verify node token exists in BWS"""
    result = {
        'success': False,
        'exists': False,
        'message': '',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get BWS token
        bws_token = get_bws_token()

        # Check if secret exists in BWS
        env = os.environ.copy()
        env['BWS_ACCESS_TOKEN'] = bws_token

        cmd = ["bws", "secret", "get", BWS_NODE_TOKEN_KEY, "--output", "json"]
        check_result = subprocess.run(cmd, capture_output=True, text=True, env=env)

        if check_result.returncode == 0:
            result['success'] = True
            result['exists'] = True
            result['message'] = f"Node token found in BWS (key: {BWS_NODE_TOKEN_KEY})"

            try:
                secret_data = json.loads(check_result.stdout)
                result['secret_id'] = secret_data.get('id')
                result['created_at'] = secret_data.get('creationDate')
                result['updated_at'] = secret_data.get('revisionDate')
            except json.JSONDecodeError:
                pass
        else:
            result['success'] = True
            result['exists'] = False
            result['message'] = f"Node token NOT found in BWS (key: {BWS_NODE_TOKEN_KEY})"

        if args.format == 'json':
            print(format_output(result, args.format))
        else:
            status = "✓" if result['exists'] else "✗"
            print(f"{status} {result['message']}")

    except Exception as e:
        result['message'] = str(e)
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def list_pvs(args):
    """List all PVs and their PVC mappings"""
    result = {
        'success': False,
        'pvs': [],
        'total_count': 0,
        'bound_count': 0,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get all PVs using Kubernetes Python client
        pv_data = get_pvs()

        pvs = []
        for pv in pv_data.get('items', []):
            pv_name = pv['metadata']['name']
            pv_status = pv['status']['phase']
            pv_capacity = pv['spec']['capacity']['storage']
            pv_storage_class = pv['spec'].get('storage_class_name', 'N/A')

            claim_ref = pv['spec'].get('claim_ref', {})
            pvc_namespace = claim_ref.get('namespace', 'N/A')
            pvc_name = claim_ref.get('name', 'N/A')

            pv_info = {
                'name': pv_name,
                'status': pv_status,
                'capacity': pv_capacity,
                'storage_class': pv_storage_class,
                'pvc_namespace': pvc_namespace,
                'pvc_name': pvc_name,
                'pvc': f"{pvc_namespace}/{pvc_name}" if pvc_namespace != 'N/A' else 'N/A'
            }

            pvs.append(pv_info)
            if pv_status == 'Bound':
                result['bound_count'] += 1

        result['pvs'] = pvs
        result['total_count'] = len(pvs)
        result['success'] = True

        if args.format == 'json':
            print(format_output(result, args.format))
        else:
            print(f"\nPersistent Volumes (Total: {result['total_count']}, Bound: {result['bound_count']})")
            print("=" * 120)
            print(f"{'PV NAME':<45} {'STATUS':<10} {'CAPACITY':<10} {'STORAGE CLASS':<20} {'PVC':<35}")
            print("-" * 120)

            for pv in sorted(pvs, key=lambda x: x['name']):
                print(f"{pv['name']:<45} {pv['status']:<10} {pv['capacity']:<10} {pv['storage_class']:<20} {pv['pvc']:<35}")
            print()

    except Exception as e:
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def backup_pvs(args):
    """Backup PV/PVC list to S3"""
    result = {
        'success': False,
        'message': '',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get all PVs (reuse logic from list_pvs)
        pv_data = get_pvs()

        pvs = []
        bound_count = 0
        for pv in pv_data.get('items', []):
            pv_name = pv['metadata']['name']
            pv_status = pv['status']['phase']
            pv_capacity = pv['spec']['capacity']['storage']
            pv_storage_class = pv['spec'].get('storage_class_name', 'N/A')

            claim_ref = pv['spec'].get('claim_ref', {})
            pvc_namespace = claim_ref.get('namespace', 'N/A')
            pvc_name = claim_ref.get('name', 'N/A')

            pv_info = {
                'name': pv_name,
                'status': pv_status,
                'capacity': pv_capacity,
                'storage_class': pv_storage_class,
                'pvc_namespace': pvc_namespace,
                'pvc_name': pvc_name,
                'pvc': f"{pvc_namespace}/{pvc_name}" if pvc_namespace != 'N/A' else 'N/A'
            }

            pvs.append(pv_info)
            if pv_status == 'Bound':
                bound_count += 1

        # Create backup data
        backup_data = {
            'cluster_name': CLUSTER_NAME,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_count': len(pvs),
            'bound_count': bound_count,
            'pvs': pvs
        }

        # Create filename with timestamp
        timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        filename = f"pv-list-{CLUSTER_NAME}-{timestamp_str}.json"
        s3_key = f"{S3_PV_BACKUP_PREFIX}{filename}"

        # Upload to S3
        bws_token = get_bws_token()
        s3_client = get_s3_client(bws_token)

        try:
            # Upload the file
            upload_response = s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=s3_key,
                Body=json.dumps(backup_data, indent=2),
                ContentType='application/json',
                Metadata={
                    'cluster': CLUSTER_NAME,
                    'backup-type': 'pv-list',
                    'timestamp': timestamp_str
                }
            )

            # Verify upload succeeded by checking the response
            if upload_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(f"S3 upload returned status code {upload_response['ResponseMetadata']['HTTPStatusCode']}")

            # Double-check the file exists
            try:
                head_response = s3_client.head_object(Bucket=S3_BUCKET, Key=s3_key)
                file_size = head_response['ContentLength']
            except ClientError as e:
                raise Exception(f"File uploaded but verification failed: {str(e)}")

            result['success'] = True
            result['message'] = f"PV list backed up to S3"
            result['s3_location'] = f"s3://{S3_BUCKET}/{s3_key}"
            result['filename'] = filename
            result['total_pvs'] = len(pvs)
            result['bound_pvs'] = bound_count
            result['file_size_bytes'] = file_size

            # Prune old backups (only after successful upload)
            prune_result = prune_old_backups(
                s3_client=s3_client,
                prefix=S3_PV_BACKUP_PREFIX,
                retention_count=RETENTION_PV_BACKUPS,
                file_pattern=f"pv-list-{CLUSTER_NAME}-"
            )
            result['pruned_count'] = prune_result['deleted_count']
            result['kept_count'] = prune_result['kept_count']
            if prune_result.get('error'):
                result['prune_error'] = prune_result['error']

            if args.format == 'json':
                print(format_output(result, args.format))
            else:
                print(f"✓ {result['message']}")
                print(f"  Location: {result['s3_location']}")
                print(f"  PVs backed up: {result['total_pvs']} (Bound: {result['bound_pvs']})")
                print(f"  File size: {file_size} bytes")
                if result['pruned_count'] > 0:
                    print(f"  Pruned {result['pruned_count']} old backup(s), kept {result['kept_count']}")

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            result['error'] = f"S3 upload failed: [{error_code}] {error_message}"
            result['error_details'] = {
                'code': error_code,
                'message': error_message,
                'bucket': S3_BUCKET,
                'key': s3_key
            }
            print(format_output(result, args.format))
            sys.exit(1)
        except Exception as e:
            result['error'] = f"Upload error: {str(e)}"
            print(format_output(result, args.format))
            sys.exit(1)

    except Exception as e:
        result['message'] = str(e)
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def backup_nodes(args):
    """Backup node information to S3"""
    result = {
        'success': False,
        'message': '',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get all nodes using Kubernetes Python client
        v1 = client.CoreV1Api()
        node_list = v1.list_node()

        nodes = []
        for node in node_list.items:
            node_name = node.metadata.name

            # Get node status
            conditions = node.status.conditions or []
            ready_condition = next((c for c in conditions if c.type == 'Ready'), None)
            status = 'Ready' if ready_condition and ready_condition.status == 'True' else 'NotReady'

            # Get roles from labels
            labels = node.metadata.labels or {}
            roles = []
            for label_key in labels.keys():
                if label_key.startswith('node-role.kubernetes.io/'):
                    role = label_key.split('/')[-1]
                    if role:
                        roles.append(role)
            role_str = ','.join(roles) if roles else '<none>'

            # Get age
            creation_time = node.metadata.creation_timestamp
            now = datetime.now(timezone.utc)
            age = now - creation_time
            age_days = age.days

            # Get version
            kubelet_version = node.status.node_info.kubelet_version

            # Get IP addresses
            addresses = node.status.addresses or []
            internal_ip = next((addr.address for addr in addresses if addr.type == 'InternalIP'), 'N/A')
            external_ip = next((addr.address for addr in addresses if addr.type == 'ExternalIP'), 'N/A')

            # Get system information
            node_info = node.status.node_info
            os_image = node_info.os_image
            kernel_version = node_info.kernel_version
            container_runtime = node_info.container_runtime_version

            node_data = {
                'name': node_name,
                'status': status,
                'roles': role_str,
                'age_days': age_days,
                'version': kubelet_version,
                'internal_ip': internal_ip,
                'external_ip': external_ip,
                'os_image': os_image,
                'kernel_version': kernel_version,
                'container_runtime': container_runtime,
                'creation_timestamp': creation_time.isoformat(),
                'labels': labels,
                'annotations': node.metadata.annotations or {},
                'capacity': {
                    'cpu': node.status.capacity.get('cpu', 'N/A'),
                    'memory': node.status.capacity.get('memory', 'N/A'),
                    'pods': node.status.capacity.get('pods', 'N/A')
                },
                'allocatable': {
                    'cpu': node.status.allocatable.get('cpu', 'N/A'),
                    'memory': node.status.allocatable.get('memory', 'N/A'),
                    'pods': node.status.allocatable.get('pods', 'N/A')
                }
            }

            nodes.append(node_data)

        # Create backup data
        backup_data = {
            'cluster_name': CLUSTER_NAME,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_count': len(nodes),
            'nodes': nodes
        }

        # Create filename with timestamp
        timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        filename = f"nodes-{CLUSTER_NAME}-{timestamp_str}.json"
        s3_key = f"{S3_NODES_BACKUP_PREFIX}{filename}"

        # Upload to S3
        bws_token = get_bws_token()
        s3_client = get_s3_client(bws_token)

        try:
            # Upload the file
            upload_response = s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=s3_key,
                Body=json.dumps(backup_data, indent=2),
                ContentType='application/json',
                Metadata={
                    'cluster': CLUSTER_NAME,
                    'backup-type': 'nodes',
                    'timestamp': timestamp_str
                }
            )

            # Verify upload succeeded
            if upload_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(f"S3 upload returned status code {upload_response['ResponseMetadata']['HTTPStatusCode']}")

            # Double-check the file exists
            try:
                head_response = s3_client.head_object(Bucket=S3_BUCKET, Key=s3_key)
                file_size = head_response['ContentLength']
            except ClientError as e:
                raise Exception(f"File uploaded but verification failed: {str(e)}")

            result['success'] = True
            result['message'] = f"Node information backed up to S3"
            result['s3_location'] = f"s3://{S3_BUCKET}/{s3_key}"
            result['filename'] = filename
            result['total_nodes'] = len(nodes)
            result['file_size_bytes'] = file_size

            # Prune old backups (only after successful upload)
            prune_result = prune_old_backups(
                s3_client=s3_client,
                prefix=S3_NODES_BACKUP_PREFIX,
                retention_count=RETENTION_NODE_BACKUPS,
                file_pattern=f"nodes-{CLUSTER_NAME}-"
            )
            result['pruned_count'] = prune_result['deleted_count']
            result['kept_count'] = prune_result['kept_count']
            if prune_result.get('error'):
                result['prune_error'] = prune_result['error']

            if args.format == 'json':
                print(format_output(result, args.format))
            else:
                print(f"✓ {result['message']}")
                print(f"  Location: {result['s3_location']}")
                print(f"  Nodes backed up: {result['total_nodes']}")
                print(f"  File size: {file_size} bytes")
                if result['pruned_count'] > 0:
                    print(f"  Pruned {result['pruned_count']} old backup(s), kept {result['kept_count']}")

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            result['error'] = f"S3 upload failed: [{error_code}] {error_message}"
            result['error_details'] = {
                'code': error_code,
                'message': error_message,
                'bucket': S3_BUCKET,
                'key': s3_key
            }
            print(format_output(result, args.format))
            sys.exit(1)
        except Exception as e:
            result['error'] = f"Upload error: {str(e)}"
            print(format_output(result, args.format))
            sys.exit(1)

    except Exception as e:
        result['message'] = str(e)
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def verify_etcd_backups(args):
    """Verify etcd backups in S3 are recent"""
    result = {
        'success': False,
        'backup_count': 0,
        'most_recent_backup': None,
        'age_hours': None,
        'within_threshold': False,
        'threshold_hours': ETCD_BACKUP_MAX_AGE_HOURS,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get BWS token and S3 client
        bws_token = get_bws_token()
        s3_client = get_s3_client(bws_token)

        # List objects in S3 bucket with etcd prefix
        try:
            response = s3_client.list_objects_v2(
                Bucket=S3_BUCKET,
                Prefix=S3_ETCD_PREFIX
            )
        except ClientError as e:
            result['error'] = f"S3 error: {str(e)}"
            print(format_output(result, args.format))
            sys.exit(1)

        if 'Contents' not in response or len(response['Contents']) == 0:
            result['error'] = f"No etcd backups found in s3://{S3_BUCKET}/{S3_ETCD_PREFIX}"
            print(format_output(result, args.format))
            sys.exit(1)

        # Find most recent backup
        backups = response['Contents']
        most_recent = max(backups, key=lambda x: x['LastModified'])

        result['backup_count'] = len(backups)
        result['most_recent_backup'] = most_recent['Key']
        result['most_recent_backup_time'] = most_recent['LastModified'].isoformat()
        result['most_recent_backup_size'] = most_recent['Size']

        # Calculate age
        now = datetime.now(timezone.utc)
        backup_time = most_recent['LastModified']
        age = now - backup_time
        age_hours = age.total_seconds() / 3600

        result['age_hours'] = round(age_hours, 2)
        result['within_threshold'] = age_hours <= ETCD_BACKUP_MAX_AGE_HOURS
        result['success'] = True

        if args.format == 'json':
            print(format_output(result, args.format))
        else:
            status = "✓" if result['within_threshold'] else "✗"
            print(f"\netcd Backup Verification")
            print("=" * 80)
            print(f"S3 Location: s3://{S3_BUCKET}/{S3_ETCD_PREFIX}")
            print(f"Total Backups: {result['backup_count']}")
            print(f"Most Recent: {result['most_recent_backup']}")
            print(f"Backup Time: {result['most_recent_backup_time']}")
            print(f"Age: {result['age_hours']:.2f} hours")
            print(f"Threshold: {ETCD_BACKUP_MAX_AGE_HOURS} hours")
            print(f"{status} Status: {'PASS' if result['within_threshold'] else 'FAIL - Backup too old!'}")
            print()

    except Exception as e:
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def verify_longhorn_backups(args):
    """Verify all PVs with valid PVCs have recent backups"""
    result = {
        'success': False,
        'total_volumes': 0,
        'backed_up_volumes': 0,
        'missing_backups': [],
        'stale_backups': [],
        'healthy_backups': [],
        'threshold_hours': LONGHORN_BACKUP_MAX_AGE_HOURS,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    try:
        # Get all PVs and PVCs using Kubernetes Python client
        pv_data = get_pvs()
        pvc_data = get_pvcs()

        # Create mapping of volume name to PVC
        volume_to_pvc = {}
        for pv in pv_data.get('items', []):
            if pv['status']['phase'] == 'Bound':
                pv_name = pv['metadata']['name']
                claim_ref = pv['spec'].get('claim_ref', {})
                pvc_namespace = claim_ref.get('namespace')
                pvc_name = claim_ref.get('name')

                if pvc_namespace and pvc_name:
                    volume_to_pvc[pv_name] = f"{pvc_namespace}/{pvc_name}"

        result['total_volumes'] = len(volume_to_pvc)

        # Get Longhorn backup volumes using custom resource API
        backup_data = get_custom_resources(
            group='longhorn.io',
            version='v1beta2',
            plural='backupvolumes',
            namespace=LONGHORN_NAMESPACE
        )

        # Create mapping of volume name to backup info
        volume_backups = {}
        for bv in backup_data.get('items', []):
            volume_name = bv['spec']['volumeName']
            last_backup = bv['status'].get('lastBackupAt', '')
            data_stored = bv['status'].get('dataStored', '0')

            # Convert data stored to GB
            try:
                data_stored_gb = int(data_stored) / (1024 ** 3)
            except (ValueError, TypeError):
                data_stored_gb = 0

            volume_backups[volume_name] = {
                'last_backup': last_backup,
                'data_stored_gb': round(data_stored_gb, 2)
            }

        # Check each volume
        now = datetime.now(timezone.utc)

        for volume_name, pvc_name in volume_to_pvc.items():
            volume_info = {
                'volume': volume_name,
                'pvc': pvc_name
            }

            if volume_name not in volume_backups:
                volume_info['status'] = 'NO_BACKUP'
                result['missing_backups'].append(volume_info)
            else:
                backup_info = volume_backups[volume_name]
                last_backup_str = backup_info['last_backup']

                if not last_backup_str:
                    volume_info['status'] = 'NO_BACKUP'
                    result['missing_backups'].append(volume_info)
                else:
                    try:
                        last_backup_time = parse_k8s_timestamp(last_backup_str)
                        age = now - last_backup_time
                        age_hours = age.total_seconds() / 3600

                        volume_info['last_backup'] = last_backup_str
                        volume_info['age_hours'] = round(age_hours, 2)
                        volume_info['data_stored_gb'] = backup_info['data_stored_gb']

                        if age_hours > LONGHORN_BACKUP_MAX_AGE_HOURS:
                            volume_info['status'] = 'STALE'
                            result['stale_backups'].append(volume_info)
                        else:
                            volume_info['status'] = 'OK'
                            result['healthy_backups'].append(volume_info)
                            result['backed_up_volumes'] += 1

                    except ValueError as e:
                        volume_info['status'] = 'PARSE_ERROR'
                        volume_info['error'] = str(e)
                        result['missing_backups'].append(volume_info)

        result['success'] = True

        if args.format == 'json':
            print(format_output(result, args.format))
        else:
            print(f"\nLonghorn Backup Verification")
            print("=" * 120)
            print(f"Total Volumes: {result['total_volumes']}")
            print(f"Backed Up: {result['backed_up_volumes']}")
            print(f"Missing Backups: {len(result['missing_backups'])}")
            print(f"Stale Backups: {len(result['stale_backups'])}")
            print(f"Threshold: {LONGHORN_BACKUP_MAX_AGE_HOURS} hours")
            print()

            if result['healthy_backups']:
                print("✓ Healthy Backups:")
                print(f"  {'VOLUME':<45} {'PVC':<35} {'LAST BACKUP':<28} {'AGE (hrs)':<10} {'SIZE (GB)':<10}")
                print("  " + "-" * 118)
                for v in sorted(result['healthy_backups'], key=lambda x: x['volume']):
                    print(f"  {v['volume']:<45} {v['pvc']:<35} {v['last_backup']:<28} {v['age_hours']:<10.2f} {v['data_stored_gb']:<10.2f}")
                print()

            if result['stale_backups']:
                print("⚠ Stale Backups (older than threshold):")
                print(f"  {'VOLUME':<45} {'PVC':<35} {'LAST BACKUP':<28} {'AGE (hrs)':<10} {'SIZE (GB)':<10}")
                print("  " + "-" * 118)
                for v in sorted(result['stale_backups'], key=lambda x: x['volume']):
                    print(f"  {v['volume']:<45} {v['pvc']:<35} {v['last_backup']:<28} {v['age_hours']:<10.2f} {v['data_stored_gb']:<10.2f}")
                print()

            if result['missing_backups']:
                print("✗ Missing Backups:")
                print(f"  {'VOLUME':<45} {'PVC':<35} {'STATUS':<20}")
                print("  " + "-" * 100)
                for v in sorted(result['missing_backups'], key=lambda x: x['volume']):
                    print(f"  {v['volume']:<45} {v['pvc']:<35} {v['status']:<20}")
                print()

            # Overall status
            if len(result['missing_backups']) == 0 and len(result['stale_backups']) == 0:
                print("✓ All volumes have recent backups")
            else:
                print("✗ Some volumes need attention!")
            print()

    except Exception as e:
        result['error'] = str(e)
        print(format_output(result, args.format))
        sys.exit(1)


def verify_all(args):
    """Run all verification checks"""
    results = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'checks': {}
    }

    # Save original format
    original_format = args.format

    # Run checks in JSON mode to capture results
    args.format = 'json'

    checks = [
        ('node_token', check_node_token),
        ('etcd_backups', verify_etcd_backups),
        ('longhorn_backups', verify_longhorn_backups),
    ]

    all_passed = True

    for check_name, check_func in checks:
        # Capture output
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        try:
            with redirect_stdout(f):
                check_func(args)
            output = f.getvalue()
            check_result = json.loads(output)
            results['checks'][check_name] = check_result

            # Determine if check passed
            if check_name == 'node_token':
                passed = check_result.get('exists', False)
            elif check_name == 'etcd_backups':
                passed = check_result.get('within_threshold', False)
            elif check_name == 'longhorn_backups':
                passed = (len(check_result.get('missing_backups', [])) == 0 and
                         len(check_result.get('stale_backups', [])) == 0)
            else:
                passed = check_result.get('success', False)

            results['checks'][check_name]['passed'] = passed
            if not passed:
                all_passed = False

        except SystemExit:
            # Check failed
            output = f.getvalue()
            try:
                check_result = json.loads(output)
            except:
                check_result = {'error': 'Check failed', 'success': False}
            results['checks'][check_name] = check_result
            results['checks'][check_name]['passed'] = False
            all_passed = False

    results['all_passed'] = all_passed

    # Restore original format
    args.format = original_format

    if args.format == 'json':
        print(json.dumps(results, indent=2, default=str))
    else:
        print("\n" + "=" * 80)
        print("k3s Cluster Verification Summary")
        print("=" * 80)

        for check_name, check_result in results['checks'].items():
            passed = check_result.get('passed', False)
            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"\n{status} - {check_name.replace('_', ' ').title()}")

            if check_name == 'node_token':
                exists = check_result.get('exists', False)
                print(f"  Node token {'exists' if exists else 'missing'} in BWS")

            elif check_name == 'etcd_backups':
                if 'age_hours' in check_result:
                    print(f"  Most recent backup: {check_result['age_hours']:.2f} hours ago")
                    print(f"  Threshold: {check_result['threshold_hours']} hours")
                else:
                    print(f"  Error: {check_result.get('error', 'Unknown error')}")

            elif check_name == 'longhorn_backups':
                total = check_result.get('total_volumes', 0)
                backed_up = check_result.get('backed_up_volumes', 0)
                missing = len(check_result.get('missing_backups', []))
                stale = len(check_result.get('stale_backups', []))

                print(f"  Total volumes: {total}")
                print(f"  Healthy backups: {backed_up}")
                if missing > 0:
                    print(f"  Missing backups: {missing}")
                if stale > 0:
                    print(f"  Stale backups: {stale}")

        print("\n" + "=" * 80)
        if all_passed:
            print("✓ All checks passed!")
        else:
            print("✗ Some checks failed - review details above")
        print("=" * 80 + "\n")


# ============================================================================
# Main CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="k3s Backup and Verification Tool - Native Kubernetes API access with Bitwarden integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s backup-node-token              # Backup k3s node token to BWS
  %(prog)s check-node-token --format json # Check if node token exists (JSON output)
  %(prog)s list-pvs                       # List all PVs and their PVCs
  %(prog)s backup-pvs                     # Backup PV/PVC list to S3
  %(prog)s backup-nodes                   # Backup node information to S3
  %(prog)s verify-etcd                    # Verify etcd backups are recent
  %(prog)s verify-longhorn                # Verify Longhorn volume backups
  %(prog)s verify-all                     # Run all verification checks

Configuration:
  All configuration is via environment variables. Required variables:
    - S3_BUCKET
    - BWS_SECRET_ID_ACCESS_KEY
    - BWS_SECRET_ID_SECRET_KEY
    - BWS_SECRET_ID_ENDPOINT
    - BWS_SECRET_ID_REGION
    - BWS_SECRET_ID_BUCKET

  See README.md for complete configuration options and examples.
        """
    )

    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # backup-node-token
    subparsers.add_parser(
        'backup-node-token',
        help='Backup k3s node token to BWS'
    )

    # check-node-token
    subparsers.add_parser(
        'check-node-token',
        help='Verify node token exists in BWS'
    )

    # list-pvs
    subparsers.add_parser(
        'list-pvs',
        help='List all PVs and their PVC mappings'
    )

    # backup-pvs
    subparsers.add_parser(
        'backup-pvs',
        help='Backup PV/PVC list to S3'
    )

    # backup-nodes
    subparsers.add_parser(
        'backup-nodes',
        help='Backup node information to S3'
    )

    # verify-etcd
    subparsers.add_parser(
        'verify-etcd',
        help='Verify etcd backups in S3 are recent'
    )

    # verify-longhorn
    subparsers.add_parser(
        'verify-longhorn',
        help='Verify Longhorn volume backups'
    )

    # verify-all
    subparsers.add_parser(
        'verify-all',
        help='Run all verification checks'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Validate configuration
    try:
        validate_config()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("See --help for required environment variables.", file=sys.stderr)
        sys.exit(1)

    # Initialize Kubernetes client
    try:
        init_k8s_client()
    except Exception as e:
        print(f"Error: Failed to initialize Kubernetes client: {e}", file=sys.stderr)
        print("Make sure your kubeconfig is properly configured.", file=sys.stderr)
        sys.exit(1)

    # Route to appropriate function
    commands = {
        'backup-node-token': backup_node_token,
        'check-node-token': check_node_token,
        'list-pvs': list_pvs,
        'backup-pvs': backup_pvs,
        'backup-nodes': backup_nodes,
        'verify-etcd': verify_etcd_backups,
        'verify-longhorn': verify_longhorn_backups,
        'verify-all': verify_all
    }

    commands[args.command](args)


if __name__ == '__main__':
    main()
