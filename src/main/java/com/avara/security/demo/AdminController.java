package com.avara.security.demo;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;

import com.avara.security.user.Role;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin-api")
public class AdminController {

  @PreAuthorize("hasRole('ADMIN')")
  @GetMapping
  public String adminEndpoint() {
    return "Hello from admin secured endpoint";
  }

  @GetMapping("/general")
  public String generalEndpoint() {
    return "Hello from general endpoint";
  }

}
