package fr.vde.springbootsecurityjwtauth.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Abdelhadi
 * @since 13-12-2023
 */
@Entity
@Table(name = "users",
  // uniqueConstraints est utilisé pour spécifier des contraintes d'unicité sur la table de base de données.
  uniqueConstraints = {
    @UniqueConstraint(columnNames = "username"),
    @UniqueConstraint(columnNames = "email")
  }
)
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  @Size(max = 20)
  private String username;

  @NotBlank
  @Size(max = 50)
  private String email;

  @NotBlank
  @Size(max = 120)
  private String password;

  @ManyToMany(fetch = FetchType.LAZY)
  /**
   * Spécifie la table intermédiaire qui gère la relation Many-to-Many entre les utilisateurs et les rôles.
   * Dans cet exemple, la table s'appelle "user_roles"
   */
  @JoinTable(name = "user_roles",
    /**
     * Colonne de la table "user_roles" qui fait référence à la clé primaire de la table "user".
    */
    joinColumns = @JoinColumn(name = "user_id"),
    /**
     * Colonne de la table "user_roles" qui fait référence à la clé primaire de la table "role".
    */
    inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();


}
