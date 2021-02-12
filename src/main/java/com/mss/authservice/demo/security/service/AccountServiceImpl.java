package com.mss.authservice.demo.security.service;

import com.mss.authservice.demo.security.entities.AppRole;
import com.mss.authservice.demo.security.entities.AppUser;
import com.mss.authservice.demo.security.repositories.AppRoleRepository;
import com.mss.authservice.demo.security.repositories.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Transactional
@Service
public class AccountServiceImpl implements AccountService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;

    public  AccountServiceImpl(AppRoleRepository appRoleRepository,
                               AppUserRepository appUserRepository,
                               PasswordEncoder passwordEncoder){
        this.appRoleRepository=appRoleRepository;
        this.appUserRepository=appUserRepository;

        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser user) {
        String userPassword=user.getPassword();
        user.setPassword(passwordEncoder.encode(userPassword));
        appUserRepository.save(user);
        return user;
    }

    @Override
    public AppRole addNewRole(AppRole role) {
        appRoleRepository.save(role);
        return role;
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser=appUserRepository.findByUsername(username);
        AppRole appRole=appRoleRepository.findByRole(roleName);

        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        AppUser user=appUserRepository.findByUsername(username);
        return user;
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
