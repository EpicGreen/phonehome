#!/bin/bash
# Webhook Notifier Example for PhoneHome Server
# This script demonstrates how to process phone home data and send notifications
# to various webhook endpoints (Slack, Discord, Teams, etc.)

set -euo pipefail

# Configuration - these can be set via environment variables
WEBHOOK_URL="${WEBHOOK_URL:-}"
WEBHOOK_TYPE="${WEBHOOK_TYPE:-slack}"  # slack, discord, teams, generic
LOG_FILE="${LOG_FILE:-/var/log/phonehome/webhook-notifier.log}"
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"

# Get the phone home data from command line argument
DATA="$1"

# Logging function
log() {
    echo "$(date -Iseconds) [$1] $2" | tee -a "$LOG_FILE"
}

# Parse pipe-separated data
parse_data() {
    IFS='|' read -ra FIELDS <<< "$DATA"
    
    # Extract fields based on expected format from cloud-init form data:
    # timestamp|instance_id|hostname|fqdn|public_ipv4|local_ipv4|cloud_name|region|availability_zone
    # Note: Cloud-init sends data as application/x-www-form-urlencoded with fields:
    # instance_id, hostname, fqdn, pub_key_rsa, pub_key_ecdsa, pub_key_ed25519
    TIMESTAMP="${FIELDS[0]:-unknown}"
    INSTANCE_ID="${FIELDS[1]:-unknown}"
    HOSTNAME="${FIELDS[2]:-unknown}"
    FQDN="${FIELDS[3]:-unknown}"
    PUB_KEY_RSA="${FIELDS[4]:-unknown}"
    PUB_KEY_ECDSA="${FIELDS[5]:-unknown}"
    PUB_KEY_ED25519="${FIELDS[6]:-unknown}"
}

# Create Slack-formatted payload
create_slack_payload() {
    cat << EOF
{
    "text": "🚀 New Cloud Instance Phone Home",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "☁️ Cloud Instance Phone Home"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Instance ID:*\n\`$INSTANCE_ID\`"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Hostname:*\n\`$HOSTNAME\`"
                },
                {
                    "type": "mrkdwn",
                    "text": "*FQDN:*\n\`$FQDN\`"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Public IP:*\n\`$PUBLIC_IP\`"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Local IP:*\n\`$LOCAL_IP\`"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Cloud Provider:*\n$CLOUD_NAME"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Region:*\n$REGION"
                },
                {
                    "type": "mrkdwn",
                    "text": "*AZ:*\n$AVAILABILITY_ZONE"
                }
            ]
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "📅 Timestamp: $TIMESTAMP"
                }
            ]
        }
    ]
}
EOF
}

# Create Discord-formatted payload
create_discord_payload() {
    cat << EOF
{
    "embeds": [
        {
            "title": "🚀 New Cloud Instance Phone Home",
            "color": 3066993,
            "timestamp": "$TIMESTAMP",
            "fields": [
                {
                    "name": "Instance ID",
                    "value": "$INSTANCE_ID",
                    "inline": true
                },
                {
                    "name": "Hostname",
                    "value": "$HOSTNAME",
                    "inline": true
                },
                {
                    "name": "FQDN",
                    "value": "$FQDN",
                    "inline": false
                },
                {
                    "name": "RSA Key",
                    "value": "$PUB_KEY_RSA",
                    "inline": false
                },
                {
                    "name": "ECDSA Key",
                    "value": "$PUB_KEY_ECDSA",
                    "inline": false
                },
                {
                    "name": "Ed25519 Key",
                    "value": "$PUB_KEY_ED25519",
                    "inline": false
                },
                {
                    "name": "Raw Data",
                    "value": "$DATA"
                }
            ]
        }
    ]
}
EOF
}

# Create Teams-formatted payload
create_teams_payload() {
    cat << EOF
{
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "0076D7",
    "summary": "New Cloud Instance Phone Home",
    "sections": [
        {
            "activityTitle": "🚀 New Cloud Instance Phone Home",
            "activitySubtitle": "Instance $INSTANCE_ID has checked in",
            "facts": [
                {
                    "name": "Instance ID",
                    "value": "$INSTANCE_ID"
                },
                {
                    "name": "Hostname",
                    "value": "$HOSTNAME"
                },
                {
                    "name": "FQDN",
                    "value": "$FQDN"
                },
                {
                    "name": "Public IP",
                    "value": "$PUBLIC_IP"
                },
                {
                    "name": "Local IP",
                    "value": "$LOCAL_IP"
                },
                {
                    "name": "Cloud Provider",
                    "value": "$CLOUD_NAME"
                },
                {
                    "name": "Region",
                    "value": "$REGION"
                },
                {
                    "name": "Availability Zone",
                    "value": "$AVAILABILITY_ZONE"
                },
                {
                    "name": "Timestamp",
                    "value": "$TIMESTAMP"
                }
            ],
            "markdown": true
        }
    ]
}
EOF
}

# Create generic JSON payload
create_generic_payload() {
    cat << EOF
{
    "event": "phone_home",
    "timestamp": "$TIMESTAMP",
    "instance": {
        "id": "$INSTANCE_ID",
        "hostname": "$HOSTNAME",
        "fqdn": "$FQDN",
        "pub_key_rsa": "$PUB_KEY_RSA",
        "pub_key_ecdsa": "$PUB_KEY_ECDSA",
        "pub_key_ed25519": "$PUB_KEY_ED25519"
    },
    "raw_data": "$DATA"
}
EOF
}

# Send webhook with retries
send_webhook() {
    local payload="$1"
    local attempt=1
    
    while [ $attempt -le $MAX_RETRIES ]; do
        log "INFO" "Sending webhook notification (attempt $attempt/$MAX_RETRIES)"
        
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "$WEBHOOK_URL")
        
        if [ "$response_code" -ge 200 ] && [ "$response_code" -lt 300 ]; then
            log "INFO" "Webhook sent successfully (HTTP $response_code)"
            return 0
        else
            log "WARN" "Webhook failed with HTTP $response_code (attempt $attempt/$MAX_RETRIES)"
            
            if [ $attempt -lt $MAX_RETRIES ]; then
                log "INFO" "Retrying in $RETRY_DELAY seconds..."
                sleep $RETRY_DELAY
            fi
        fi
        
        ((attempt++))
    done
    
    log "ERROR" "Failed to send webhook after $MAX_RETRIES attempts"
    return 1
}

# Main function
main() {
    log "INFO" "Processing phone home data: $DATA"
    
    # Validate webhook URL
    if [ -z "$WEBHOOK_URL" ]; then
        log "ERROR" "WEBHOOK_URL environment variable is not set"
        exit 1
    fi
    
    # Parse the data
    parse_data
    
    log "INFO" "Parsed data - Instance: $INSTANCE_ID, Hostname: $HOSTNAME, FQDN: $FQDN"
    
    # Create payload based on webhook type
    local payload
    case "$WEBHOOK_TYPE" in
        "slack")
            payload=$(create_slack_payload)
            ;;
        "discord")
            payload=$(create_discord_payload)
            ;;
        "teams")
            payload=$(create_teams_payload)
            ;;
        "generic")
            payload=$(create_generic_payload)
            ;;
        *)
            log "ERROR" "Unknown webhook type: $WEBHOOK_TYPE"
            exit 1
            ;;
    esac
    
    # Send the webhook
    if send_webhook "$payload"; then
        log "INFO" "Phone home notification sent successfully"
    else
        log "ERROR" "Failed to send phone home notification"
        exit 1
    fi
}

# Run main function
main