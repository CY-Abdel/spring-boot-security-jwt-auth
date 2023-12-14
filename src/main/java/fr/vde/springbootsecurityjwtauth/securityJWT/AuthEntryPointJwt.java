package fr.vde.springbootsecurityjwtauth.securityJWT;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

  /**
   * crée une instance du logger SLF4J pour la classe AuthEntryPointJwt, permettant ainsi d'enregistrer des messages de journalisation (logs) dans votre application. Cela peut être utile pour suivre et déboguer le comportement de votre code.
   * on peut aussi ajouter la dependence @Slf4j
   */
  private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    // Journalisation de l'erreur non autorisée
    logger.error("Unauthorized error: {}", authException.getMessage());

    // Configuration de la réponse HTTP
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    // Création d'un corps JSON pour la réponse
    final Map<String, Object> body = new HashMap<>();
    body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
    body.put("error", "Unauthorized");
    body.put("message", authException.getMessage());
    body.put("path", request.getServletPath());

    // Utilisation d'ObjectMapper pour écrire le corps JSON dans le flux de sortie de la réponse
    final ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(response.getOutputStream(), body);
  }
}
