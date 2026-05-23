// NiScamKeApplication.java
// main application class for the NiScamKe backend, responsible for bootstrapping the Spring Boot application and enabling caching yey


package com.niscamke.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class NiScamKeApplication {

    public static void main(String[] args) {
        SpringApplication.run(NiScamKeApplication.class, args);
    }

    
}