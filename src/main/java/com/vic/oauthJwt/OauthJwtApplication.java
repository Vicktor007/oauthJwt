package com.vic.oauthJwt;

import com.vic.oauthJwt.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class OauthJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthJwtApplication.class, args);
	}

}
