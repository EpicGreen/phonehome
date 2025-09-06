#!/usr/bin/env bash

# Script to create source tarball for RPM packaging
# This prepares the source for builds

set -e

PACKAGE_NAME="phonehome"
VERSION="0.1.0"
TARBALL_NAME="${PACKAGE_NAME}-${VERSION}.tar.gz"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -f "src/main.rs" ]]; then
    echo "Error: Please run this script from the pushover project directory"
    exit 1
fi

print_info "Creating source tarball for ${PACKAGE_NAME} v${VERSION}..."

# Create temporary directory
TEMP_DIR=$(mktemp -d)
SOURCE_DIR="${TEMP_DIR}/${PACKAGE_NAME}-${VERSION}"

print_info "Copying source files to ${SOURCE_DIR}..."

# Create source directory structure
mkdir -p "${SOURCE_DIR}"

# Copy essential files for building
cp -r src/ "${SOURCE_DIR}/"
cp -r etc/ "${SOURCE_DIR}/"
cp Cargo.toml "${SOURCE_DIR}/"
cp Cargo.lock "${SOURCE_DIR}/" 2>/dev/null || echo "Note: Cargo.lock not found, will be generated during build"
cp LICENSE "${SOURCE_DIR}/"
cp README.md "${SOURCE_DIR}/"
cp CHANGELOG.md "${SOURCE_DIR}/"
cp pushover.spec "${SOURCE_DIR}/"
cp install.sh "${SOURCE_DIR}/"

# Create the tarball
print_info "Creating tarball ${TARBALL_NAME}..."
cd "${TEMP_DIR}"
tar -czf "${TARBALL_NAME}" "${PACKAGE_NAME}-${VERSION}/"

# Move tarball to current directory
mv "${TARBALL_NAME}" "${OLDPWD}/"

# Cleanup
rm -rf "${TEMP_DIR}"

print_success "Tarball created: ${TARBALL_NAME}"
print_info "Ready for upload!"
