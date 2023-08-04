package com.personal.jwt.controller;

import com.personal.jwt.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    @Autowired
    TokenService tokenService;

    @GetMapping("/token")
    public String startSecured(Authentication authentication){
        return tokenService.generateToken(authentication);
    }
}
