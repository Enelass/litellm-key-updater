#!/usr/bin/env zsh
#
# LiteLLM Key Updater Installation Script
# Checks for existing installation and sets up the environment
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="$HOME/Applications/LiteLLM-key-updater"
GITHUB_ZIP_URL="https://github.com/user/litellm-key-updater/archive/refs/heads/main.zip"  # PLACEHOLDER URL
REQUIRED_PY_FILES=("get_bearer.py" "renew_key.py" "check_key.py" "utils.py")

# Functions
print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 is not installed. Please install it first."
        return 1
    fi
    return 0
}

check_directory_exists() {
    if [[ -d "$INSTALL_DIR" ]]; then
        print_info "Directory $INSTALL_DIR exists"
        return 0
    else
        print_info "Directory $INSTALL_DIR does not exist"
        return 1
    fi
}

check_py_files_exist() {
    local missing_files=()
    
    for file in "${REQUIRED_PY_FILES[@]}"; do
        if [[ ! -f "$INSTALL_DIR/$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -eq 0 ]]; then
        print_success "All required Python files found"
        return 0
    else
        print_warning "Missing Python files: ${missing_files[*]}"
        return 1
    fi
}

download_and_extract() {
    print_info "Downloading from GitHub..."
    
    # Create Applications directory if it doesn't exist
    mkdir -p "$HOME/Applications"
    
    # Create temporary directory for download
    local temp_dir=$(mktemp -d)
    local zip_file="$temp_dir/litellm-key-updater.zip"
    
    print_info "Downloading to $temp_dir"
    
    if curl -L -o "$zip_file" "$GITHUB_ZIP_URL"; then
        print_success "Download completed"
    else
        print_error "Failed to download from GitHub"
        rm -rf "$temp_dir"
        return 1
    fi
    
    print_info "Extracting archive..."
    
    # Extract to temp directory first
    if unzip -q "$zip_file" -d "$temp_dir"; then
        print_success "Archive extracted"
    else
        print_error "Failed to extract archive"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Find the extracted directory (usually has -main suffix)
    local extracted_dir=$(find "$temp_dir" -type d -name "*litellm-key-updater*" | head -1)
    
    if [[ -z "$extracted_dir" ]]; then
        print_error "Could not find extracted directory"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Move to final location
    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Removing existing installation"
        rm -rf "$INSTALL_DIR"
    fi
    
    mv "$extracted_dir" "$INSTALL_DIR"
    rm -rf "$temp_dir"
    
    print_success "Installation files extracted to $INSTALL_DIR"
    return 0
}

setup_virtual_environment() {
    print_info "Setting up virtual environment with uv..."
    
    # Check if uv is installed
    if ! check_command "uv"; then
        print_error "uv is required but not installed"
        print_info "Install uv with: curl -LsSf https://astral.sh/uv/install.sh | sh"
        return 1
    fi
    
    # Change to project directory
    cd "$INSTALL_DIR"
    
    # Check if pyproject.toml exists
    if [[ ! -f "pyproject.toml" ]]; then
        print_error "pyproject.toml not found in $INSTALL_DIR"
        return 1
    fi
    
    print_info "Creating virtual environment..."
    if uv venv; then
        print_success "Virtual environment created"
    else
        print_error "Failed to create virtual environment"
        return 1
    fi
    
    print_info "Installing dependencies..."
    if uv pip install -e .; then
        print_success "Dependencies installed"
    else
        print_error "Failed to install dependencies"
        return 1
    fi
    
    print_success "Virtual environment setup complete"
    print_info "To activate: source $INSTALL_DIR/.venv/bin/activate"
    return 0
}

# Main execution
main() {
    print_info "LiteLLM Key Updater Installation Script"
    print_info "======================================="
    
    # Check if directory exists and has required files
    if check_directory_exists && check_py_files_exist; then
        print_success "Installation already exists and appears complete"
        print_info "Location: $INSTALL_DIR"
        
        # Still check/setup virtual environment
        if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
            print_info "Virtual environment not found, setting up..."
            if ! setup_virtual_environment; then
                exit 1
            fi
        else
            print_success "Virtual environment already exists"
        fi
        
        print_success "Installation check complete"
        return 0
    fi
    
    # Need to download and install
    print_info "Installation not found or incomplete, downloading..."
    
    # Check required tools
    if ! check_command "curl"; then
        exit 1
    fi
    
    if ! check_command "unzip"; then
        exit 1
    fi
    
    # Download and extract
    if ! download_and_extract; then
        exit 1
    fi
    
    # Verify files after extraction
    if ! check_py_files_exist; then
        print_error "Installation incomplete - some Python files are still missing"
        exit 1
    fi
    
    # Setup virtual environment
    if ! setup_virtual_environment; then
        exit 1
    fi
    
    print_success "Installation completed successfully!"
    print_info "Location: $INSTALL_DIR"
    print_info "To use: cd $INSTALL_DIR && source .venv/bin/activate"
}

# Run main function
main "$@"