package fr.vde.springbootsecurityjwtauth.controllers;

import fr.vde.springbootsecurityjwtauth.DTO.request.LoginRequest;
import fr.vde.springbootsecurityjwtauth.DTO.request.SignupRequest;
import fr.vde.springbootsecurityjwtauth.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:5173", maxAge = 3600)
@RestController
@RequestMapping("/auth")
public class AuthController {

  @Autowired
  AuthService authService;

  @PostMapping("/signin") // se connecter
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    return authService.authenticateUser(loginRequest);
  }

  @PostMapping("/signup") // se connecter
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
    return authService.registerUser(signupRequest);
  }
}
