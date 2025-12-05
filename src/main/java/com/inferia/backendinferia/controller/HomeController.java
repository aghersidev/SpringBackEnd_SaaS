package com.inferia.backendinferia.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "¡La aplicación está up y running!";
    }

    @GetMapping("/home2")
    public String home2() {
        return "¡La aplicación está up y running!";
    }
}