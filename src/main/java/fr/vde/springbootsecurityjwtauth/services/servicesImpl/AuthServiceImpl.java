package fr.vde.springbootsecurityjwtauth.services.servicesImpl;

import fr.vde.springbootsecurityjwtauth.DTO.request.LoginRequest;
import fr.vde.springbootsecurityjwtauth.services.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;


@Service
public class AuthServiceImpl implements AuthService {

  @Override
  public ResponseEntity<?> authenticateUser(LoginRequest loginRequest) {

    return null;
  }
}
