#!/bin/bash
set -e

echo "Starting report processing..."

# Retrieve bucket from environment variable
ScanResultBucket=${RESULTS_BUCKET}
echo "Using S3 bucket: $ScanResultBucket"

# Retrieve SSH keys and config if transfer is enabled
TRANSFER_TO_REMOTE=$(aws ssm get-parameter --name /devsecops/TRANSFER_TO_REMOTE --query "Parameter.Value" --output text --with-decryption || echo "false")

if [ "$TRANSFER_TO_REMOTE" = "true" ]; then
    echo "Remote transfer enabled. Setting up SSH access."

    # Retrieve keys from AWS Secrets Manager
    JUMP_HOST_PrivateKey=$(aws ssm get-parameter --name /devsecops/JUMP_HOST_PrivateKey --with-decryption --query "Parameter.Value" --output text)
    REMOTE_SERVER_PrivateKey=$(aws ssm get-parameter --name /devsecops/REMOTE_SERVER_PrivateKey --with-decryption --query "Parameter.Value" --output text)
    JUMP_HOST=$(aws ssm get-parameter --name /devsecops/JUMP_HOST --with-decryption --query "Parameter.Value" --output text)
    REMOTE_SERVER=$(aws ssm get-parameter --name /devsecops/REMOTE_SERVER --with-decryption --query "Parameter.Value" --output text)
    REMOTE_USER=$(aws ssm get-parameter --name /devsecops/REMOTE_USER --with-decryption --query "Parameter.Value" --output text || echo "inuser")
    SSH_CONFIG=$(aws ssm get-parameter --name /devsecops/SSH_CONFIG --with-decryption --query "Parameter.Value" --output text)

    # Configure SSH
    mkdir -p ~/.ssh
    echo "$JUMP_HOST_PrivateKey" > ~/.ssh/JHP_id_rsa
    cat ~/.ssh/JHP_id_rsa
    echo "$REMOTE_SERVER_PrivateKey" > ~/.ssh/RSP_id_rsa
    cat ~/.ssh/RSP_id_rsa
    echo "$SSH_CONFIG" > ~/.ssh/config
    chmod 600 ~/.ssh/JHP_id_rsa ~/.ssh/RSP_id_rsa ~/.ssh/config
    ssh-keyscan $JUMP_HOST >> ~/.ssh/known_hosts 2>/dev/null || true
    ssh-keyscan $REMOTE_SERVER >> ~/.ssh/known_hosts 2>/dev/null || true
else
    echo "Remote transfer disabled. Will only process reports locally."
fi

echo "Creating reports directory"
mkdir -p reports

# Download JSON files for each tool if available
for TOOL in kubescape trivy dependency-check; do
    echo "Checking for results in $TOOL folder"
    mkdir -p ./reports/$TOOL
    if aws s3 ls s3://$ScanResultBucket/$TOOL/ 2>/dev/null; then
        echo "Tool folder $TOOL exists in bucket"
        aws s3 cp s3://$ScanResultBucket/$TOOL/ ./reports/$TOOL/ --recursive --exclude "*" --include "*.json" || echo "No files to copy for $TOOL"
    else
        echo "No folder for $TOOL in the bucket"
    fi
done

# Count downloaded files
FILE_COUNT=$(find ./reports -type f -name "*.json" | wc -l)
echo "Downloaded $FILE_COUNT report files"

# Create a summary file
cat > ./summary-report.json <<EOF
{
  "scanTime": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "filesProcessed": $FILE_COUNT,
  "tools": {
    "kubescape": $(find ./reports/kubescape -type f -name "*.json" | wc -l),
    "trivy": $(find ./reports/trivy -type f -name "*.json" | wc -l),
    "dependencyCheck": $(find ./reports/dependency-check -type f -name "*.json" | wc -l)
  }
}
EOF

# Transfer to remote server if enabled
if [ "$TRANSFER_TO_REMOTE" = "true" ]; then
    echo "Transferring files to remote server"
    ssh -i ~/.ssh/RSP_id_rsa -o StrictHostKeyChecking=no ${REMOTE_USER}@${REMOTE_SERVER} "mkdir -p /home/${REMOTE_USER}/reports"

    # Transfer and rename files
    for TOOL in kubescape trivy dependency-check; do
        if [ -d "./reports/$TOOL" ]; then
            find ./reports/$TOOL -type f -name "*.json" | while read FILE; do
                if [ -s "$FILE" ]; then
                    DIRNAME=$(dirname "$FILE")
                    TIMESTAMP=$(basename "$DIRNAME" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}" || echo "$(date +%Y-%m-%d-%H-%M)")
                    FILENAME=$(basename "$FILE")
                    NEW_FILENAME="${TOOL}_${TIMESTAMP}_${FILENAME}"
                    echo "Transferring $FILE as $NEW_FILENAME"
                    scp -i ~/.ssh/RSP_id_rsa -o StrictHostKeyChecking=no "$FILE" ${REMOTE_USER}@${REMOTE_SERVER}:/home/${REMOTE_USER}/reports/"$NEW_FILENAME"
                else
                    echo "Skipping empty file: $FILE"
                fi
            done
        fi
    done

    # Transfer summary report
    scp -i ~/.ssh/RSP_id_rsa -o StrictHostKeyChecking=no ./summary-report.json ${REMOTE_USER}@${REMOTE_SERVER}:/home/${REMOTE_USER}/reports/summary_$(date +%Y-%m-%d-%H-%M).json
fi

# Upload summary to S3
echo "Uploading summary to S3"
aws s3 cp ./summary-report.json s3://$ScanResultBucket/summary/$(date +%Y-%m-%d-%H-%M)-summary.json || echo "Failed to upload summary"

# Clean up SSH keys
if [ "$TRANSFER_TO_REMOTE" = "true" ]; then
    echo "Cleaning up SSH keys"
    rm -f ~/.ssh/JHP_id_rsa ~/.ssh/RSP_id_rsa ~/.ssh/config ~/.ssh/known_hosts
fi

echo "Process completed successfully"

