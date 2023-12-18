package fr.vde.springbootsecurityjwtauth.config;

import fr.vde.springbootsecurityjwtauth.models.ERole;
import fr.vde.springbootsecurityjwtauth.models.Role;
import fr.vde.springbootsecurityjwtauth.securityJWT.AuthEntryPointJwt;
import fr.vde.springbootsecurityjwtauth.securityJWT.AuthTokenFilter;
import fr.vde.springbootsecurityjwtauth.services.servicesImpl.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  @Autowired
  UserDetailsServiceImpl userDetailsService;

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .csrf(AbstractHttpConfigurer::disable)

      .authorizeHttpRequests(auth -> auth
        .requestMatchers("/auth/**").permitAll()
        .requestMatchers("/test/all").permitAll()
        .requestMatchers("/test/admin").hasAnyAuthority(ERole.ROLE_ADMIN.name())
        .requestMatchers("/test/mod").hasAnyAuthority(ERole.ROLE_ADMIN.name(), ERole.ROLE_MODERATOR.name())
        .anyRequest().authenticated()
      )
      .exceptionHandling(exception -> exception
        .authenticationEntryPoint(unauthorizedHandler))

      .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


    http.authenticationProvider(authenticationProvider());

    http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

    authenticationProvider.setUserDetailsService(userDetailsService);
    authenticationProvider.setPasswordEncoder(passwordEncoder());

    return authenticationProvider;
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfing) throws Exception {
    return authConfing.getAuthenticationManager();
  }


}
