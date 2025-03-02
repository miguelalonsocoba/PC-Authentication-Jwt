package com.pc.springsecurity.authenticationjwt.services;

import com.pc.springsecurity.authenticationjwt.domain.dtos.NewUserDto;
import com.pc.springsecurity.authenticationjwt.domain.entities.Role;
import com.pc.springsecurity.authenticationjwt.domain.entities.User;
import com.pc.springsecurity.authenticationjwt.domain.enums.Roles;
import com.pc.springsecurity.authenticationjwt.domain.repositories.IRoleRepository;
import com.pc.springsecurity.authenticationjwt.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserService userService;
    private final IRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    public AuthService(UserService userService, IRoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    public String authenticate(String username, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authenticationResult = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authenticationResult);
        return jwtUtil.generateToken(authenticationResult);
    }

    public void registerUser(NewUserDto newUserDto) {
        if (userService.existByUsername(newUserDto.getUsername())) {
            throw new IllegalArgumentException("User already exists");
        }
        Role roleUser = roleRepository.findByName(Roles.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found"));
        User user = new User(newUserDto.getUsername(), passwordEncoder.encode(newUserDto.getPassword()), roleUser);
        userService.save(user);
    }

}
