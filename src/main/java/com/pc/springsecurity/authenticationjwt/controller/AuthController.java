package com.pc.springsecurity.authenticationjwt.controller;

import com.pc.springsecurity.authenticationjwt.domain.dtos.LoginUserDto;
import com.pc.springsecurity.authenticationjwt.domain.dtos.NewUserDto;
import com.pc.springsecurity.authenticationjwt.services.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(value = "/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginUserDto loginUserDto, BindingResult bindingResult) {
        LOGGER.info("Executing login endpoint with username: {}, password: {} ", loginUserDto.getUsername(), loginUserDto.getPassword());
        if (bindingResult.hasErrors()) {
            LOGGER.error("Binding result has errors: {}", bindingResult.getAllErrors());
            return ResponseEntity.badRequest().body("Invalid username or password. Please check your credentials and try again.");
        }
        try {
            String jwt = authService.authenticate(loginUserDto.getUsername(), loginUserDto.getPassword());
            return ResponseEntity.ok(jwt);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid username or password. Please check your credentials and try again.");
        }
    }

    @PostMapping(value = "/register")
    public ResponseEntity<String> register(@Valid @RequestBody NewUserDto newUserDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseEntity.badRequest().body("Check the input fields and try again.");
        }
        try {
            authService.registerUser(newUserDto);
            return ResponseEntity.status(HttpStatus.CREATED).body("Registration successful.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping(value = "/check-auth")
    public ResponseEntity<String> checkAuth() {
        return ResponseEntity.ok().body("Authenticated");
    }
}
