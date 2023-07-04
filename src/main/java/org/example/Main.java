package org.example;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;

// TUTORIALS TO SEE:

// 1. https://www.viralpatel.net/java-create-validate-jwt-token/
// 2. https://github.com/jwtk/jjwt
public class Main {
    public static void main(String[] args) {

        String secret = "asdfSFS34wfsdfsdfSDSD32dfsddDDerQSNCK34SOWEK5354fdgdf4";
        JWTManager jwtManager = new JWTManager(secret);

        // 1. createToken
        String jwtToken = jwtManager.createToken(
                "Subject-Here",
                "Issuer-Here",
                86400);

        // 2. getClaims from token
        Jws<Claims> jwtClaims = null;
        try {
            jwtClaims = jwtManager.getClaims(jwtToken);
        } catch(ExpiredJwtException expiredJwtException) {
            System.out.println("token has expired! " + expiredJwtException.getLocalizedMessage());
            System.exit(0); // end the program
        } catch(SignatureException signatureException) {
            System.out.println("token has not a valid signature with given secret! " + signatureException.getLocalizedMessage());
            System.exit(0); // end the program
        }
        System.out.println("jwtClaims are " + jwtClaims);

        // 3. Verify claims: issuer and subject
        Boolean isIssuerAndSubjectValid = jwtManager.verifySubjectAndIssuer(jwtClaims,"Subject-Here", "Issuer-Here");
        System.out.println("isIssuerAndSubjectValid");

    }
}