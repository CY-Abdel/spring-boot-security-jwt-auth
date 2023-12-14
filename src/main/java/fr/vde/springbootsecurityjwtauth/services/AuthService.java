package fr.vde.springbootsecurityjwtauth.services;

import fr.vde.springbootsecurityjwtauth.DTO.request.LoginRequest;
import fr.vde.springbootsecurityjwtauth.DTO.request.SignupRequest;
import org.springframework.http.ResponseEntity;

public interface AuthService {
  ResponseEntity<?> authenticateUser(LoginRequest loginRequest);

  ResponseEntity<?> registerUser(SignupRequest signupRequest);
}
