package com.niscamke.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for Verification Service response with extended details.
 * Used internally for richer response handling.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationServiceDTO {
    private String status;          // ALLOW, BLOCK, WARN
    private String threatLevel;     // LOW, MEDIUM, HIGH
    private int riskScore;          // 0-100
    private String detectionSource; // FAST_PATH, AI_ANALYSIS, REGISTRY
    private String reason;
}
