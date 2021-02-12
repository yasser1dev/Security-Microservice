package com.mss.authservice.demo.security.dto;

import com.mss.authservice.demo.security.entities.AppRole;
import com.mss.authservice.demo.security.entities.AppUser;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @NoArgsConstructor @AllArgsConstructor
public class UserRoleModel {
    private String user;
    private String role;
}
