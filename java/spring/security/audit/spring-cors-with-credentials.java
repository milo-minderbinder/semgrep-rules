package testcode.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


@SpringBootApplication
@EnableWebSecurity
public class UnsafeCORSSpringBootApplication {

    @RestController
    // ruleid:spring-cors-with-credentials
    @CrossOrigin(origins = "*", allowCredentials = "true")
    public static class UnsafeController {

        // ruleid:spring-cors-with-credentials
        @CrossOrigin(allowCredentials = "true")
        @GetMapping("/{id}")
        public Long unsafeRetrieve(@PathVariable Long id) {
            return id;
        }

        @DeleteMapping("/{id}")
        // ruleid:spring-cors-with-credentials
        @CrossOrigin(origins = "*", allowCredentials = "true")
        public void remove(@PathVariable Long id) {
        }
    }

    @RestController
    // ok
    @CrossOrigin(origins = "https://domain2.com", allowCredentials = "true", maxAge = 3600)
    public static class SafeController {

        // ok
        @CrossOrigin(origins = "*")
        @GetMapping("/")
        public String index() {
            return "redirect:index.html";
        }

        // ok
        @CrossOrigin
        @GetMapping("/{id}")
        public Long retrieve(@PathVariable Long id) {
            return id;
        }

        @DeleteMapping("/{id}")
        @CrossOrigin(allowCredentials = "false")
        public void remove(@PathVariable Long id) {
        }
    }

    @Bean
    public WebMvcConfigurer unsafeCorsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // ruleid:global-spring-cors-with-credentials
                registry.addMapping("/*")
                        .allowedOrigins("*", "http://example.com")
                        .allowCredentials(true).allowedMethods("PUT");
            }
        };
    }

    @Bean
    public WebMvcConfigurer safeCorsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            // ok
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/*")
                        .allowedOrigins("http://example.com")
                        .allowedMethods("GET")
                        .allowCredentials(true);
            }
        };
    }

    @Configuration
    public static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests().anyRequest().permitAll().and()
                    .cors();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            // ruleid:spring-security-cors-with-credentials
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.applyPermitDefaultValues();
            configuration.setAllowCredentials(true);
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }
    }
}

