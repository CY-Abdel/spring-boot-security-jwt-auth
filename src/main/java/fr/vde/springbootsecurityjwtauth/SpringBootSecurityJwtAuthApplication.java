package fr.vde.springbootsecurityjwtauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication (exclude = SecurityAutoConfiguration.class)
public class SpringBootSecurityJwtAuthApplication implements CommandLineRunner {

  public static void main(String[] args) {
    SpringApplication.run(SpringBootSecurityJwtAuthApplication.class, args);
  }

  @Autowired
  private JdbcTemplate jdbcTemplate;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) throws Exception {
    // Vérifier si les rôles existent avant d'insérer
    if (jdbcTemplate.queryForObject("SELECT COUNT(*) FROM roles", Integer.class) == 0) {
      // Exécutez vos requêtes SQL ici
      jdbcTemplate.execute("INSERT INTO roles(name) VALUES('ROLE_USER')");
      jdbcTemplate.execute("INSERT INTO roles(name) VALUES('ROLE_MODERATOR')");
      jdbcTemplate.execute("INSERT INTO roles(name) VALUES('ROLE_ADMIN')");
    }
    // Vérifier si l'administrateur existe avant d'insérer
    if (!userExists("admin")) {
      insertUser("admin", "admin@vde.com", passwordEncoder.encode("admin"), "ROLE_ADMIN");
    }

    // Vérifier si le modérateur existe avant d'insérer
    if (!userExists("moderator")) {
      insertUser("moderator", "moderator@vde.com", passwordEncoder.encode("moderator"), "ROLE_MODERATOR");
    }
  }

  private boolean userExists(String username) {
    Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users WHERE username = ?", Integer.class, username);
    return count != null && count > 0;
  }

  private void insertUser(String username, String email, String password, String role) {
    jdbcTemplate.update("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, password);
    Integer userId = jdbcTemplate.queryForObject("SELECT id FROM users WHERE username = ?", Integer.class, username);

    Integer roleId = jdbcTemplate.queryForObject("SELECT id FROM roles WHERE name = ?", Integer.class, role);

    jdbcTemplate.update("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", userId, roleId);
  }
}
