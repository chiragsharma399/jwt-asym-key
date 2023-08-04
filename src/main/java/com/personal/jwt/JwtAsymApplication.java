package com.personal.jwt;

import com.personal.jwt.security.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class JwtAsymApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAsymApplication.class, args);
	}

}
