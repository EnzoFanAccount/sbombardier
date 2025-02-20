package sbombardier

# Default to false if no explicit allow
default allow = false

# Define license compatibility matrix
license_compatibility = {
    "MIT": ["MIT", "Apache-2.0", "GPL-3.0", "AGPL-3.0"],
    "Apache-2.0": ["MIT", "Apache-2.0"],
    "GPL-3.0": ["GPL-3.0", "AGPL-3.0"],
    "AGPL-3.0": ["AGPL-3.0"]
}

# Check if all licenses are compatible with project license
allow {
    # Get project license from input
    project_license := input.project_license
    
    # Check if all dependency licenses are compatible
    all_compatible := all([
        is_compatible(license, project_license) |
        license := input.licenses[_]
    ])
    
    all_compatible
}

# Helper function to check if two licenses are compatible
is_compatible(dep_license, proj_license) {
    # Check if the dependency license is in the compatibility list for the project license
    compatible_licenses := license_compatibility[proj_license]
    dep_license == proj_license
} else {
    compatible_licenses := license_compatibility[proj_license]
    dep_license in compatible_licenses
} 