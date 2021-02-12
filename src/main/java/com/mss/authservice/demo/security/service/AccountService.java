package com.mss.authservice.demo.security.service;

import com.mss.authservice.demo.security.entities.AppRole;
import com.mss.authservice.demo.security.entities.AppUser;
import org.springframework.stereotype.Service;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser user);
    AppRole addNewRole(AppRole role);
    void addRoleToUser(String username,String roleName);// fail , we better affect role to user by user id
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
