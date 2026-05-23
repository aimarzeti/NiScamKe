package com.niscamke.backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.niscamke.backend.model.FalsePositiveReport;

public interface FalsePositiveReportRepository extends JpaRepository<FalsePositiveReport, Long> {
    List<FalsePositiveReport> findByStatus(String status);
    long countByStatus(String status);
}
