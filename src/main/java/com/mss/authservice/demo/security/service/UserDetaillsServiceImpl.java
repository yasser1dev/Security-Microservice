package com.mss.authservice.demo.security.service;

import com.mss.authservice.demo.security.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;


@Service
public class UserDetaillsServiceImpl implements UserDetailsService {

    private AccountService accountService;

    public UserDetaillsServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser=accountService.loadUserByUsername(username);
        Collection<GrantedAuthority> authorities=appUser.getAppRoles()
                .stream().map((role)->new SimpleGrantedAuthority(role.getRole()))
                .collect(Collectors.toList());
        return new User(appUser.getUsername(),appUser.getPassword(),authorities);
    }
}
