# GitHub Actions Setup for Docker Hub

This document describes how to configure GitHub Actions to automatically build and push Docker images to Docker Hub.

## Overview

The repository includes a GitHub Actions workflow (`.github/workflows/build-and-push.yml`) that automatically:
- Builds the Docker image on every push to `main` and on version tags
- Pushes the image to Docker Hub
- Updates the Docker Hub repository description

## Prerequisites

- A Docker Hub account
- Admin access to your GitHub repository

## Setup Instructions

### 1. Create Docker Hub Access Token

1. Log in to [Docker Hub](https://hub.docker.com)
2. Click your username (top right) → **Account Settings**
3. Go to **Security** → **Access Tokens**
4. Click **New Access Token**
5. Configure the token:
   - **Description**: `github-actions-k3s-metadata-backup` (or any name you prefer)
   - **Access permissions**: **Read, Write & Delete**
6. Click **Generate**
7. **Copy the token immediately** - you won't be able to see it again!

### 2. Add Secrets to GitHub Repository

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**

#### Add DOCKER_HUB_USERNAME

- **Name**: `DOCKER_HUB_USERNAME`
- **Value**: Your Docker Hub username (e.g., `johndoe`)
- Click **Add secret**

#### Add DOCKER_HUB_TOKEN

- **Name**: `DOCKER_HUB_TOKEN`
- **Value**: The access token you created in step 1
- Click **Add secret**

### 3. Verify Setup

The workflow will automatically trigger on:
- Push to `main` branch
- Creating version tags (e.g., `v1.0.0`)
- Pull requests to `main` (build only, no push)

To manually trigger a build:
1. Go to the **Actions** tab in your repository
2. Find any previous workflow run
3. Click **Re-run jobs** → **Re-run failed jobs** (if it previously failed)

Or simply push a commit to trigger the workflow:
```bash
git commit --allow-empty -m "Trigger CI build"
git push
```

## What Gets Built

The workflow creates the following Docker images:

### On Push to Main Branch
- `<username>/k3s-metadata-backup:main`
- `<username>/k3s-metadata-backup:latest`

### On Version Tags (e.g., `git tag v1.2.3`)
- `<username>/k3s-metadata-backup:1.2.3`
- `<username>/k3s-metadata-backup:1.2`
- `<username>/k3s-metadata-backup:1`
- `<username>/k3s-metadata-backup:latest`

### On Pull Requests
- Image is built but **not pushed** to Docker Hub (validation only)

## Creating Version Releases

To create a new versioned release:

```bash
# Tag the commit
git tag v1.0.0
git push origin v1.0.0
```

This will trigger the workflow and push version-tagged images to Docker Hub.

## Troubleshooting

### Build Fails with "authentication required"

**Cause**: GitHub secrets are not configured or are incorrect.

**Solution**:
- Verify both secrets exist in **Settings** → **Secrets and variables** → **Actions**
- Ensure `DOCKER_HUB_TOKEN` is a valid access token (not your password)
- Regenerate the Docker Hub access token if needed

### Image Pushes Successfully but Description Not Updated

**Cause**: The `peter-evans/dockerhub-description` action requires both username and token.

**Solution**:
- Verify both `DOCKER_HUB_USERNAME` and `DOCKER_HUB_TOKEN` are set correctly
- Check that the token has **Read & Write** permissions

### Build Succeeds but Can't Find Image on Docker Hub

**Cause**: The repository might not exist on Docker Hub yet.

**Solution**:
- The first push will automatically create the repository
- Verify the image name matches: `<your-username>/k3s-metadata-backup`
- Check the **Actions** tab to confirm the push step succeeded (green checkmark)

## Security Notes

- **Never commit Docker Hub credentials to Git**
- Use access tokens instead of passwords for better security
- Access tokens can be revoked without changing your password
- Repository secrets are encrypted and only available to workflow runs
- Tokens are not exposed in workflow logs
