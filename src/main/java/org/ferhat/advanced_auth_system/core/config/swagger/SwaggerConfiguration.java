package org.ferhat.advanced_auth_system.core.config.swagger;


import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;

@Configuration
public class SwaggerConfiguration {
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Advanced Authentication System")
                        .description("Advanced Authentication System REST API")
                        .contact(new Contact().name("Ferhat"))
                        .version("1.0.0"))
                .components(new Components()
                        .addSecuritySchemes("bearer-jwt", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT token için 'Bearer ' öneki ile birlikte girin")))
                .addSecurityItem(new SecurityRequirement().addList("bearer-jwt"));
    }
}
