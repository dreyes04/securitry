package com.security.security.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/cards")
public class Cards {

    @GetMapping
    public Map<String, String> getCards() {
        return Map.of("card", "1234567891234567");
    }
}
