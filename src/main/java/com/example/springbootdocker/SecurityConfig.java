package com.example.springbootdocker;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

import javax.servlet.http.HttpServletRequest;

import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

    	// add auto-generation of ServiceProvider Metadata
    	// default url: {baseUrl}/saml2/service-provider-metadata/{registrationId}
        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
                new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);

        //using new constructor method creates error (ambiguous contstructor)
        Saml2MetadataFilter filter = new Saml2MetadataFilter(
                relyingPartyRegistrationResolver,
                new OpenSamlMetadataResolver());
        

        http
        	.saml2Login(saml2 -> saml2.loginProcessingUrl("/custom/{registrationId}"))
            .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class)
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/detail/**").authenticated();
        
        // by default, spring will create a basic logout page
        http
	        .logout()
	        .addLogoutHandler((request, response, authentication) -> {
	            try {
					response.sendRedirect("/detail");	//logout page: set to main page or logout or login page
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
	        });
    }
}