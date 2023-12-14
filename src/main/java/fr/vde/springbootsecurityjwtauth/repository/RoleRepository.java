package fr.vde.springbootsecurityjwtauth.repository;

import fr.vde.springbootsecurityjwtauth.models.ERole;
import fr.vde.springbootsecurityjwtauth.models.Role;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository {
  Optional<Role> findByName(ERole name);
}
