package com.niscamke.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Simple DTO for verification responses.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class VerificationResponseDTO {
    private String status;
    private String reason;
}

