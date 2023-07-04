package org.example;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;


public class JWTManager {
    public String secretKey;
    public Key keyHashed;
    public JWTManager(String secretKey)
    {
        this.secretKey = secretKey;
        // hashing key --- volendo si può hashare con un algoritmo diverso
        this.keyHashed = new SecretKeySpec(Base64.getDecoder().decode(secretKey), SignatureAlgorithm.HS256.getJcaName());
    }

    public String createToken(String subject, String issuer, long secondsToExpiration)
    {
        Instant now = Instant.now();
        String jwtToken = Jwts.builder()
                //.claim("name", "Jane Doe")
                //.claim("email", "jane@example.com")
                .setSubject(subject)
                .setIssuer(issuer)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(secondsToExpiration, ChronoUnit.SECONDS)))
                .signWith(keyHashed)
                .compact();
        return jwtToken;
    }

    // Note: if the token is expired, it throws ExpiredJwtException
    // Note: if the signature is not valid, it throws SignatureException
    public Jws<Claims> getClaims(String jwtToken) throws ExpiredJwtException, SignatureException
    {
        Jws<Claims> jwtClaims = Jwts.parserBuilder()
                .setSigningKey(keyHashed)
                .build()
                .parseClaimsJws(jwtToken);
        return jwtClaims;
    }

    public Boolean verifySubjectAndIssuer(Jws<Claims> jwtClaims, String subjectToVerify, String issuerToVerify)
    {
        Claims payload = jwtClaims.getBody();
        Boolean verifyIssuer = payload.getIssuer().equals(issuerToVerify);
        Boolean verifySubject = payload.getSubject().equals(subjectToVerify);

        if(verifyIssuer && verifySubject)
        {
            return true;
        } else {
            return false;
        }
    }



}
