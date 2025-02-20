package sbombardier

# Default to false if no explicit allow
default allow = false

# Define GDPR-sensitive regions
gdpr_regions = ["EU", "EEA", "UK"]

# Define high-risk data categories
high_risk_data = ["personal_data", "biometric", "health", "financial"]

# Allow if all GDPR requirements are met
allow {
    # Check data processing requirements
    valid_data_processing
    
    # Check data storage locations
    valid_storage_locations
    
    # Check security measures
    valid_security_measures
}

# Validate data processing requirements
valid_data_processing {
    input.data_processing.purpose
    input.data_processing.legal_basis
    input.data_processing.retention_period
}

# Validate data storage locations
valid_storage_locations {
    storage_locations := { location | location := input.storage_locations[_] }
    
    # Check if any storage location is in GDPR regions
    some location in storage_locations
    location in gdpr_regions
}

# Validate security measures
valid_security_measures {
    required_measures := {
        "encryption",
        "access_control",
        "data_backup",
        "incident_response"
    }
    
    implemented_measures := { measure | measure := input.security_measures[_] }
    
    # All required measures must be implemented
    required_measures_implemented := required_measures & implemented_measures
    count(required_measures_implemented) == count(required_measures)
}

# Additional rules for high-risk data processing
deny {
    # Check if processing high-risk data
    some data_type in input.data_types
    data_type in high_risk_data
    
    # Check if additional safeguards are missing
    not has_additional_safeguards
}

# Helper to check additional safeguards for high-risk data
has_additional_safeguards {
    input.security_measures.dpia_completed
    input.security_measures.dpo_approved
    input.security_measures.encryption_at_rest
    input.security_measures.encryption_in_transit
} 