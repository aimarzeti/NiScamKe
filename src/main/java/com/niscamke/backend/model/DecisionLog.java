package com.niscamke.backend.model;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "decision_logs", indexes = {
        @Index(name = "idx_decision_public_id", columnList = "public_id", unique = true),
        @Index(name = "idx_decision_domain", columnList = "domain_name"),
        @Index(name = "idx_decision_created_at", columnList = "created_at")
})
public class DecisionLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id", nullable = false, unique = true, updatable = false, length = 36)
    private String publicId;

    @Column(name = "url", nullable = false, length = 1200)
    private String url;

    @Column(name = "domain_name", nullable = false, length = 255)
    private String domainName;

    @Column(name = "decision", nullable = false, length = 16)
    private String decision;

    @Column(name = "risk_score", nullable = false)
    private Integer riskScore;

    @Column(name = "confidence", nullable = false)
    private Double confidence;

    @Column(name = "reason", nullable = false, length = 1000)
    private String reason;

    @Column(name = "evidence_sources", nullable = false, length = 255)
    private String evidenceSources;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.publicId == null || this.publicId.isBlank()) {
            this.publicId = UUID.randomUUID().toString();
        }
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }
}
