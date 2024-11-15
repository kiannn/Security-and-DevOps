package com.example.demo.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import static com.auth0.jwt.algorithms.Algorithm.HMAC384;
import com.example.demo.model.persistence.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	 private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
            HttpServletResponse res) throws AuthenticationException {
        try {
            User credentials = new ObjectMapper()
                    .readValue(req.getInputStream(), User.class);

            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            credentials.getUsername(),
                            credentials.getPassword(),
                            new ArrayList<>()));
            
            return authenticate;
            
        } catch (IOException e) {
            
            throw new RuntimeException(e);
        }
    }
    
    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

          //system.out.println("\nsuccessfulAuthentication()");
        String token = JWT.create()
                .withHeader(Map.of("typ","JWT","alg","HS384")) 
                .withIssuedAt(new Date())
                .withSubject( auth.getName())
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                .sign(HMAC384(SecurityConstants.SECRET.getBytes()));
        
           //system.out.println("HEADER is -> "+new String(Base64.getUrlDecoder().decode(token.substring(0, token.indexOf('.')))));
//         String header = JWT.require(HMAC384(SecurityConstants.SECRET.getBytes()))
//                             .build()
//                             .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""))
//                             .getHeader();
  
          //system.out.println("HEADER is  -->"+new String(Base64.getUrlDecoder().decode(header)));

        res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
    }
}
