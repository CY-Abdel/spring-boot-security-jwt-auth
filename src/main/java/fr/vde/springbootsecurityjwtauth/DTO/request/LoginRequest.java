package fr.vde.springbootsecurityjwtauth.DTO.request;

public class LoginRequest {

  private Object message = "connexion reussi";

  public LoginRequest(Object message) {
    this.message = message;
  }

  public Object getMessage() {
    return message;
  }

  public void setMessage(Object message) {
    this.message = message;
  }
}
