package com.avara.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService authenticationService;

  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody RegisterRequest request) {
    return ResponseEntity.ok(authenticationService.registerUser(request));
  }

  @PostMapping("/register-admin")
  public ResponseEntity<AuthenticationResponse> registerAdmin(@RequestBody RegisterRequest request) {
    return ResponseEntity.ok(authenticationService.registerAdmin(request));
  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
    return ResponseEntity.ok(authenticationService.authenticate(request));
  }

}
