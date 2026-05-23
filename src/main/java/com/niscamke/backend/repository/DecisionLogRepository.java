package com.niscamke.backend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.niscamke.backend.model.DecisionLog;

public interface DecisionLogRepository extends JpaRepository<DecisionLog, Long> {
    Optional<DecisionLog> findByPublicId(String publicId);
}
