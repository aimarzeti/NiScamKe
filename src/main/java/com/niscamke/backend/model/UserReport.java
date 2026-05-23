package com.niscamke.backend.model;

import java.time.LocalDateTime;

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
@Table(name = "user_reports", indexes = {
        @Index(name = "idx_user_reports_domain", columnList = "domain_name"),
        @Index(name = "idx_user_reports_status", columnList = "status"),
        @Index(name = "idx_user_reports_created_at", columnList = "created_at")
})
public class UserReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "url", nullable = false, length = 1200)
    private String url;

    @Column(name = "domain_name", nullable = false, length = 255)
    private String domainName;

    @Column(name = "reporter_email", length = 255)
    private String reporterEmail;

    @Column(name = "scam_type", nullable = false, length = 64)
    private String scamType;

    @Column(name = "description", length = 1000)
    private String description;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.status == null || this.status.isBlank()) {
            this.status = "PENDING_REVIEW";
        }
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
    }
}
