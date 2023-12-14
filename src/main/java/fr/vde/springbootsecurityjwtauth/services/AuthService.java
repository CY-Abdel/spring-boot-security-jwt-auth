package fr.vde.springbootsecurityjwtauth.services;

import fr.vde.springbootsecurityjwtauth.DTO.request.LoginRequest;
import org.springframework.http.ResponseEntity;

public interface AuthService {
  ResponseEntity<?> authenticateUser(LoginRequest loginRequest);
}
