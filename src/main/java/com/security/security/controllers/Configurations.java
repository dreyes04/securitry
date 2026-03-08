package com.security.security.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/configurations")
public class Configurations {

    @RequestMapping
    public Map<String, String> getConfigurations() {
        return Map.of("configurations", "example");
    }
}
