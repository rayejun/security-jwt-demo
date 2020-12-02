package io.github.rayejun.securityjwt.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

    private static final byte[] SECRET = DigestUtils.md5DigestAsHex(Constants.AUTHORIZATION_SECRET.getBytes()).getBytes(StandardCharsets.UTF_8);

    public static String createToken(String username, String id, List<GrantedAuthority> authorities) {
        try {
            MACSigner macSigner = new MACSigner(SECRET);
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(username)
                    .expirationTime(new Date(System.currentTimeMillis() + Constants.AUTHORIZATION_EXPIRE_TIME))
                    .jwtID(id)
                    .claim(Constants.AUTHORITIES_KEY, authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                    .build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(macSigner);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            logger.error("createToken", e);
        }
        return null;
    }

    public static void validateToken(String token) throws RuntimeException {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(SECRET);

            if (!jwt.verify(verifier)) {
                throw new RuntimeException("Token is invalid");
            }

            Date expirationTime = jwt.getJWTClaimsSet().getExpirationTime();
            if (new Date().after(expirationTime)) {
                throw new RuntimeException("Token is expired");
            }
        } catch (ParseException | JOSEException e) {
            logger.error("validateToken", e);
            throw new RuntimeException("Token is invalid");
        }
    }
}
