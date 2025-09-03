#!/bin/bash
# Database Logger Example for PhoneHome Server
# This script demonstrates how to process phone home data and store it in a database
# Supports MySQL, PostgreSQL, and SQLite

set -euo pipefail

# Configuration - these can be set via environment variables
DB_TYPE="${DB_TYPE:-sqlite}"  # mysql, postgresql, sqlite
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-phonehome}"
DB_USER="${DB_USER:-phonehome}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_FILE="${DB_FILE:-/var/lib/phonehome/phonehome.db}"
LOG_FILE="${LOG_FILE:-/var/log/phonehome/database-logger.log}"
TABLE_NAME="${TABLE_NAME:-phone_home_events}"

# Get the phone home data from command line argument
DATA="$1"

# Logging function
log() {
    echo "$(date -Iseconds) [$1] $2" | tee -a "$LOG_FILE"
}

# Parse pipe-separated data
parse_data() {
    IFS='|' read -ra FIELDS <<< "$DATA"
    
    # Extract fields based on expected format:
    # timestamp|instance_id|hostname|public_ipv4|local_ipv4|cloud_name|region
    TIMESTAMP="${FIELDS[0]:-$(date -Iseconds)}"
    INSTANCE_ID="${FIELDS[1]:-unknown}"
    HOSTNAME="${FIELDS[2]:-unknown}"
    PUBLIC_IP="${FIELDS[3]:-}"
    LOCAL_IP="${FIELDS[4]:-}"
    CLOUD_NAME="${FIELDS[5]:-unknown}"
    REGION="${FIELDS[6]:-unknown}"
    
    # Clean up empty values
    [ "$PUBLIC_IP" = "" ] && PUBLIC_IP="NULL"
    [ "$LOCAL_IP" = "" ] && LOCAL_IP="NULL"
    [ "$REGION" = "" ] && REGION="NULL"
}

# Create table if it doesn't exist
create_table() {
    local create_sql
    
    case "$DB_TYPE" in
        "mysql")
            create_sql="CREATE TABLE IF NOT EXISTS $TABLE_NAME (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                instance_id VARCHAR(255) NOT NULL,
                hostname VARCHAR(255) NOT NULL,
                public_ip VARCHAR(45),
                local_ip VARCHAR(45),
                cloud_name VARCHAR(100) NOT NULL,
                region VARCHAR(100),
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_instance_id (instance_id),
                INDEX idx_timestamp (timestamp),
                INDEX idx_cloud_name (cloud_name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
            ;;
        "postgresql")
            create_sql="CREATE TABLE IF NOT EXISTS $TABLE_NAME (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                instance_id VARCHAR(255) NOT NULL,
                hostname VARCHAR(255) NOT NULL,
                public_ip INET,
                local_ip INET,
                cloud_name VARCHAR(100) NOT NULL,
                region VARCHAR(100),
                raw_data TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_instance_id ON $TABLE_NAME (instance_id);
            CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_timestamp ON $TABLE_NAME (timestamp);
            CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_cloud_name ON $TABLE_NAME (cloud_name);"
            ;;
        "sqlite")
            create_sql="CREATE TABLE IF NOT EXISTS $TABLE_NAME (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                public_ip TEXT,
                local_ip TEXT,
                cloud_name TEXT NOT NULL,
                region TEXT,
                raw_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_instance_id ON $TABLE_NAME (instance_id);
            CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_timestamp ON $TABLE_NAME (timestamp);
            CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_cloud_name ON $TABLE_NAME (cloud_name);"
            ;;
    esac
    
    execute_sql "$create_sql"
}

# Execute SQL command
execute_sql() {
    local sql="$1"
    
    case "$DB_TYPE" in
        "mysql")
            if [ -n "$DB_PASSWORD" ]; then
                mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" <<< "$sql"
            else
                mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "$DB_NAME" <<< "$sql"
            fi
            ;;
        "postgresql")
            export PGPASSWORD="$DB_PASSWORD"
            psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$sql"
            ;;
        "sqlite")
            sqlite3 "$DB_FILE" "$sql"
            ;;
    esac
}

# Insert phone home data
insert_data() {
    local insert_sql
    local escaped_hostname escaped_cloud_name escaped_region escaped_raw_data
    
    # Escape single quotes for SQL
    escaped_hostname=$(echo "$HOSTNAME" | sed "s/'/''/g")
    escaped_cloud_name=$(echo "$CLOUD_NAME" | sed "s/'/''/g")
    escaped_region=$(echo "$REGION" | sed "s/'/''/g")
    escaped_raw_data=$(echo "$DATA" | sed "s/'/''/g")
    
    case "$DB_TYPE" in
        "mysql"|"postgresql")
            if [ "$PUBLIC_IP" = "NULL" ] || [ "$LOCAL_IP" = "NULL" ] || [ "$escaped_region" = "NULL" ]; then
                insert_sql="INSERT INTO $TABLE_NAME (timestamp, instance_id, hostname, public_ip, local_ip, cloud_name, region, raw_data) 
                           VALUES ('$TIMESTAMP', '$INSTANCE_ID', '$escaped_hostname', 
                                   $([ "$PUBLIC_IP" = "NULL" ] && echo "NULL" || echo "'$PUBLIC_IP'"), 
                                   $([ "$LOCAL_IP" = "NULL" ] && echo "NULL" || echo "'$LOCAL_IP'"), 
                                   '$escaped_cloud_name', 
                                   $([ "$escaped_region" = "NULL" ] && echo "NULL" || echo "'$escaped_region'"), 
                                   '$escaped_raw_data');"
            else
                insert_sql="INSERT INTO $TABLE_NAME (timestamp, instance_id, hostname, public_ip, local_ip, cloud_name, region, raw_data) 
                           VALUES ('$TIMESTAMP', '$INSTANCE_ID', '$escaped_hostname', '$PUBLIC_IP', '$LOCAL_IP', '$escaped_cloud_name', '$escaped_region', '$escaped_raw_data');"
            fi
            ;;
        "sqlite")
            insert_sql="INSERT INTO $TABLE_NAME (timestamp, instance_id, hostname, public_ip, local_ip, cloud_name, region, raw_data) 
                       VALUES ('$TIMESTAMP', '$INSTANCE_ID', '$escaped_hostname', 
                               $([ "$PUBLIC_IP" = "NULL" ] && echo "NULL" || echo "'$PUBLIC_IP'"), 
                               $([ "$LOCAL_IP" = "NULL" ] && echo "NULL" || echo "'$LOCAL_IP'"), 
                               '$escaped_cloud_name', 
                               $([ "$escaped_region" = "NULL" ] && echo "NULL" || echo "'$escaped_region'"), 
                               '$escaped_raw_data');"
            ;;
    esac
    
    execute_sql "$insert_sql"
}

# Check database connectivity
check_database() {
    log "INFO" "Checking database connectivity..."
    
    case "$DB_TYPE" in
        "mysql")
            if ! command -v mysql &> /dev/null; then
                log "ERROR" "mysql client not found. Please install mysql-client."
                exit 1
            fi
            
            if [ -n "$DB_PASSWORD" ]; then
                mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1;" "$DB_NAME" &> /dev/null
            else
                mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -e "SELECT 1;" "$DB_NAME" &> /dev/null
            fi
            ;;
        "postgresql")
            if ! command -v psql &> /dev/null; then
                log "ERROR" "psql client not found. Please install postgresql-client."
                exit 1
            fi
            
            export PGPASSWORD="$DB_PASSWORD"
            psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" &> /dev/null
            ;;
        "sqlite")
            if ! command -v sqlite3 &> /dev/null; then
                log "ERROR" "sqlite3 not found. Please install sqlite3."
                exit 1
            fi
            
            # Create directory if it doesn't exist
            mkdir -p "$(dirname "$DB_FILE")"
            
            # Test SQLite database
            sqlite3 "$DB_FILE" "SELECT 1;" &> /dev/null
            ;;
        *)
            log "ERROR" "Unsupported database type: $DB_TYPE"
            exit 1
            ;;
    esac
    
    log "INFO" "Database connectivity check passed"
}

# Get statistics
get_statistics() {
    local stats_sql="SELECT 
        COUNT(*) as total_events,
        COUNT(DISTINCT instance_id) as unique_instances,
        COUNT(DISTINCT cloud_name) as cloud_providers,
        MIN(timestamp) as first_event,
        MAX(timestamp) as last_event
        FROM $TABLE_NAME;"
    
    log "INFO" "Database statistics:"
    execute_sql "$stats_sql"
}

# Cleanup old records (optional)
cleanup_old_records() {
    local retention_days="${RETENTION_DAYS:-30}"
    local cleanup_sql
    
    case "$DB_TYPE" in
        "mysql")
            cleanup_sql="DELETE FROM $TABLE_NAME WHERE created_at < DATE_SUB(NOW(), INTERVAL $retention_days DAY);"
            ;;
        "postgresql")
            cleanup_sql="DELETE FROM $TABLE_NAME WHERE created_at < NOW() - INTERVAL '$retention_days days';"
            ;;
        "sqlite")
            cleanup_sql="DELETE FROM $TABLE_NAME WHERE created_at < datetime('now', '-$retention_days days');"
            ;;
    esac
    
    log "INFO" "Cleaning up records older than $retention_days days"
    execute_sql "$cleanup_sql"
}

# Main function
main() {
    log "INFO" "Processing phone home data: $DATA"
    
    # Parse the data
    parse_data
    
    log "INFO" "Parsed data - Instance: $INSTANCE_ID, Hostname: $HOSTNAME, Cloud: $CLOUD_NAME"
    
    # Check database connectivity
    check_database
    
    # Create table if needed
    create_table
    
    # Insert the data
    if insert_data; then
        log "INFO" "Phone home data inserted successfully into $DB_TYPE database"
    else
        log "ERROR" "Failed to insert phone home data"
        exit 1
    fi
    
    # Optional: cleanup old records
    if [ "${CLEANUP_ENABLED:-false}" = "true" ]; then
        cleanup_old_records
    fi
    
    # Optional: show statistics
    if [ "${SHOW_STATS:-false}" = "true" ]; then
        get_statistics
    fi
    
    log "INFO" "Database logging completed successfully"
}

# Handle script arguments
case "${1:-}" in
    "--help"|"-h")
        cat << EOF
Database Logger for PhoneHome Server

Environment Variables:
  DB_TYPE          Database type (mysql, postgresql, sqlite) [default: sqlite]
  DB_HOST          Database host [default: localhost]
  DB_PORT          Database port [default: 3306 for MySQL, 5432 for PostgreSQL]
  DB_NAME          Database name [default: phonehome]
  DB_USER          Database user [default: phonehome]
  DB_PASSWORD      Database password
  DB_FILE          SQLite database file [default: /var/lib/phonehome/phonehome.db]
  TABLE_NAME       Table name [default: phone_home_events]
  LOG_FILE         Log file location [default: /var/log/phonehome/database-logger.log]
  RETENTION_DAYS   Days to keep records [default: 30]
  CLEANUP_ENABLED  Enable automatic cleanup [default: false]
  SHOW_STATS       Show database statistics [default: false]

Examples:
  # SQLite (default)
  DB_TYPE=sqlite ./database_logger.sh "2024-01-15T10:30:00Z|i-123|host1|1.2.3.4|10.0.1.1|aws|us-west-2"
  
  # MySQL
  DB_TYPE=mysql DB_HOST=localhost DB_USER=phonehome DB_PASSWORD=secret \\
    ./database_logger.sh "2024-01-15T10:30:00Z|i-123|host1|1.2.3.4|10.0.1.1|aws|us-west-2"
  
  # PostgreSQL
  DB_TYPE=postgresql DB_HOST=localhost DB_PORT=5432 DB_USER=phonehome DB_PASSWORD=secret \\
    ./database_logger.sh "2024-01-15T10:30:00Z|i-123|host1|1.2.3.4|10.0.1.1|aws|us-west-2"
EOF
        exit 0
        ;;
    "--init")
        # Initialize database
        log "INFO" "Initializing database..."
        check_database
        create_table
        log "INFO" "Database initialized successfully"
        exit 0
        ;;
    "--stats")
        # Show statistics only
        check_database
        get_statistics
        exit 0
        ;;
    "--cleanup")
        # Run cleanup only
        check_database
        cleanup_old_records
        exit 0
        ;;
esac

# Run main function if data is provided
if [ $# -eq 0 ]; then
    echo "Error: Phone home data argument required"
    echo "Use --help for usage information"
    exit 1
fi

main