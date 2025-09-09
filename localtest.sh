#!/usr/bin/env bash

# RPM Local Test Script - Fixed Version
set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
if ! command -v rpmbuild &> /dev/null; then
    print_error "rpmbuild not found. Install with: sudo dnf install rpm-build rpmdevtools"
    exit 1
fi

# Set up RPM build environment if needed
if [ ! -d "$HOME/rpmbuild" ]; then
    print_info "Setting up RPM build environment..."
    rpmdev-setuptree
fi

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -f "phonehome.spec" ]; then
    print_error "Please run this script from the phonehome project directory"
    exit 1
fi

# Get version from spec file to ensure consistency
VERSION=$(grep "^Version:" phonehome.spec | awk '{print $2}')
if [ -z "$VERSION" ]; then
    print_error "Could not extract version from phonehome.spec"
    exit 1
fi

print_info "Building RPM for phonehome version: $VERSION"

PACKAGE_NAME="phonehome"
TARBALL_NAME="${PACKAGE_NAME}-${VERSION}.tar.gz"

# Store current directory
ORIGINAL_DIR=$(pwd)

# 1. Create source tarball locally (simulate GitHub action)
print_info "Creating source tarball..."

TEMP_DIR=$(mktemp -d)
SOURCE_DIR="${TEMP_DIR}/${PACKAGE_NAME}-${VERSION}"
mkdir -p "${SOURCE_DIR}"

# Copy essential files (same as GitHub action)
cp -r src/ "${SOURCE_DIR}/"
cp -r etc/ "${SOURCE_DIR}/"
cp -r usr/ "${SOURCE_DIR}/"
cp -r tests/ "${SOURCE_DIR}/"
cp -r examples/ "${SOURCE_DIR}/"
cp Cargo.toml "${SOURCE_DIR}/"
cp Cargo.lock "${SOURCE_DIR}/" 2>/dev/null || echo "Note: Cargo.lock not found"
cp LICENSE "${SOURCE_DIR}/"
cp README.md "${SOURCE_DIR}/"
cp phonehome.spec "${SOURCE_DIR}/"

# Create tarball
cd "${TEMP_DIR}"
tar -czf "${TARBALL_NAME}" "${PACKAGE_NAME}-${VERSION}/"
mv "${TARBALL_NAME}" "$HOME/"

# Cleanup temp directory
rm -rf "${TEMP_DIR}"

# Return to original directory
cd "$ORIGINAL_DIR"

print_success "Tarball created: $HOME/${TARBALL_NAME}"

# 2. Build RPM from local tarball
print_info "Building RPM..."
rpmbuild -ta "$HOME/${TARBALL_NAME}"

# Find the built RPM
RPM_FILE=$(find ~/rpmbuild/RPMS/x86_64/ -name "${PACKAGE_NAME}-${VERSION}*.rpm" -type f | head -1)

if [ -z "$RPM_FILE" ]; then
    print_error "RPM build failed - no RPM file found"
    exit 1
fi

print_success "RPM built successfully: $RPM_FILE"

# 3. Show install command (don't auto-install to avoid sudo issues)
print_info "To install the RPM, run:"
echo "sudo dnf install \"$RPM_FILE\""

# Optional: Show RPM info
print_info "RPM information:"
rpm -qpi "$RPM_FILE"

print_success "RPM test completed! RPM is ready for installation."
