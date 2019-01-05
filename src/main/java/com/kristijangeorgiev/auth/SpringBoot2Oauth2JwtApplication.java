package com.kristijangeorgiev.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * 
 * @author Kristijan Georgiev
 *
 */
@SpringBootApplication
@Configuration
@EnableAutoConfiguration
@ComponentScan
public class SpringBoot2Oauth2JwtApplication {
	
	

	public static void main(String[] args) {
		SpringApplication.run(SpringBoot2Oauth2JwtApplication.class, args);
	}

}