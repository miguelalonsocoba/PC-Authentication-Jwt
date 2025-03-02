package com.pc.springsecurity.authenticationjwt.domain.repositories;

import com.pc.springsecurity.authenticationjwt.domain.entities.Role;
import com.pc.springsecurity.authenticationjwt.domain.enums.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IRoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(Roles name);
}
