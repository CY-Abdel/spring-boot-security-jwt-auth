package fr.vde.springbootsecurityjwtauth.services.servicesImpl;

import fr.vde.springbootsecurityjwtauth.DTO.request.LoginRequest;
import fr.vde.springbootsecurityjwtauth.DTO.request.SignupRequest;
import fr.vde.springbootsecurityjwtauth.DTO.response.JwtResponse;
import fr.vde.springbootsecurityjwtauth.DTO.response.MessageResponse;
import fr.vde.springbootsecurityjwtauth.models.ERole;
import fr.vde.springbootsecurityjwtauth.models.Role;
import fr.vde.springbootsecurityjwtauth.models.User;
import fr.vde.springbootsecurityjwtauth.repository.RoleRepository;
import fr.vde.springbootsecurityjwtauth.repository.UserRepository;
import fr.vde.springbootsecurityjwtauth.securityJWT.JwtUtils;
import fr.vde.springbootsecurityjwtauth.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@Service
public class AuthServiceImpl implements AuthService {


  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  JwtUtils jwtUtils;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Override
  public ResponseEntity<?> authenticateUser(LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);

    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    List<String> roles = userDetails.getAuthorities().stream()
      .map(item -> item.getAuthority())
      .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt,
      userDetails.getId(),
      userDetails.getUsername(),
      userDetails.getEmail(),
      roles));
  }

  @Override
  public ResponseEntity<?> registerUser(SignupRequest signUpRequest) {

    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
        .badRequest()
        .body(new MessageResponse("Error: username is already taken"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity
        .badRequest()
        .body(new MessageResponse("Error: email is already in use!"));
    }

    // Creer un user si le email et le username sont disponible
    User user = new User(
      signUpRequest.getUsername(),
      signUpRequest.getEmail(),
      encoder.encode(signUpRequest.getPassword())
    );

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if ( strRoles == null ) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);

            break;
          case "mod":
            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
            roles.add(modRole);

            break;

          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    User userToSave = user;
    userRepository.save(userToSave);

    return ResponseEntity.ok(
      new MessageResponse("User created successfully!")
    );
  }
}












