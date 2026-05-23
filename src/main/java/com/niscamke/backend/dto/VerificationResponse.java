package com.niscamke.backend.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for verification response with extended details.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerificationResponse {
    private String status;          // "BLOCK", "WARN", "ALLOW"
    private String reason;
    private int riskScore;          // 0–100
    private String threatLevel;     // "HIGH", "MEDIUM", "LOW", "SAFE"
    private String detectionSource; // "DATABASE", "AI_ANALYSIS", "FAST_PATH"
    private List<String> signals;   // what triggered the flag
}
