package com.artemisa;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configurable
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Value ("${Security.jwt.client-id}")
	private String clientId;

	@Value("${Security.jwt.client-secret}")
	private String clientServer;
	
	@Value("${security.jwt.grant-type}")
	private String grantType;
	
	@Value("${security.jwt.scope-read}")
	private String scopeRead;
	
	@Value("${security.jwt.scope-write}")
	private String scopeWrite = "write";
	
	@Value("${security.jwt.resource-ids}")
	private String resourceIds;
	
	@Autowired
	private Token
}
