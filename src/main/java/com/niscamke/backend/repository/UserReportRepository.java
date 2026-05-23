package com.niscamke.backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.niscamke.backend.model.UserReport;

public interface UserReportRepository extends JpaRepository<UserReport, Long> {
}
