package org.ferhat.advanced_auth_system;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import javax.crypto.SecretKey;

@SpringBootApplication
@EnableJpaAuditing  // Necessary for timestamp management
public class AdvancedAuthSystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdvancedAuthSystemApplication.class, args);


     //  SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
     //  System.out.println("Generated Key: " + Encoders.BASE64.encode(key.getEncoded()));
    }

}
