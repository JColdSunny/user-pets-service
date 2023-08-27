package com.jcoldsun.ups.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class UserRestController {

    @GetMapping("/{id}")
    public ResponseEntity<Integer> getUserDetails(@PathVariable Integer id) {
        return ResponseEntity.ok(id);
    }

}
