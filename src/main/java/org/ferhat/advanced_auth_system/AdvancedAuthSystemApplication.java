package org.ferhat.advanced_auth_system;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@ComponentScan(basePackages = {"org.ferhat.advanced_auth_system.core.config.swagger", "org.ferhat.advanced_auth_system"})
@EnableJpaAuditing  // Timestamp yönetimi için gerekli
public class AdvancedAuthSystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdvancedAuthSystemApplication.class, args);
    }

}
