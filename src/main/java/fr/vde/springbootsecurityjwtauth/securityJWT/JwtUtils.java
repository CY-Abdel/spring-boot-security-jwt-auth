package fr.vde.springbootsecurityjwtauth.securityJWT;

import fr.vde.springbootsecurityjwtauth.models.User;
import fr.vde.springbootsecurityjwtauth.services.servicesImpl.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  // value in application.propreties
  @Value("${juba.app.jwtSecret}")
  private String jwtSecret;

  // value in application.propreties
  // we can also do -> @Value("${bezkoder.app.jwtExpirationMs}")
  @Value("$juba.app.jwtExpirationMs")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
      .setSubject((userPrincipal.getUsername()))
      .setIssuedAt(new Date())
      .setExpiration(new Date(
        (new Date()).getTime() + jwtExpirationMs))
      .signWith(key(), SignatureAlgorithm.ES256)
      .compact();
  }

  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parser()
      .setSigningKey(key())
      .build()
      .parseClaimsJws(token)
      .getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser()
        .setSigningKey(key())
        .build()
        .parse(authToken);

      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }


}
