package com.mss.authservice.demo.security.repositories;

import com.mss.authservice.demo.security.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findByRole(String role);

}
