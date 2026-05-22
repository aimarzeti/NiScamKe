// ScamRegistryRepository.java
// for managing scam registry data in the database

package com.niscamke.backend.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.niscamke.backend.model.ScamRegistry;

public interface ScamRegistryRepository extends JpaRepository<ScamRegistry, Long> {
    Optional<ScamRegistry> findByDomainName(String domainName);
}