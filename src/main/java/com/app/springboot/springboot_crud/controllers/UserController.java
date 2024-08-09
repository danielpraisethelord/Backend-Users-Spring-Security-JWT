package com.app.springboot.springboot_crud.controllers;

import java.util.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.springboot.springboot_crud.entities.User;
import com.app.springboot.springboot_crud.repositories.UserService;

import jakarta.validation.Valid;

/**
 * La anotación @CrossOrigin en Spring se utiliza para habilitar CORS
 * (Cross-Origin Resource Sharing) en tus controladores o métodos específicos.
 * CORS es una política de seguridad de los navegadores web que restringe las
 * solicitudes HTTP que pueden ser realizadas desde un origen diferente al de la
 * aplicación web que está sirviendo la solicitud. La anotación @CrossOrigin
 * permite configurar qué orígenes externos (dominios) pueden acceder a los
 * recursos de tu aplicación.
 * 
 * ¿Por qué es necesaria?
 * En la web, el "origen" de una solicitud es definido por el esquema
 * (HTTP/HTTPS), el dominio, y el puerto. Por ejemplo, si tu aplicación está en
 * https://miapp.com, y un frontend alojado en https://otraapp.com intenta hacer
 * una solicitud HTTP a tu backend, el navegador bloqueará esta solicitud debido
 * a las restricciones de CORS. @CrossOrigin te permite configurar tu backend
 * para permitir tales solicitudes.
 * 
 * Uso de @CrossOrigin
 * La anotación @CrossOrigin puede aplicarse a:
 * 
 * Un controlador entero: Permite el acceso a todos los métodos del controlador
 * desde los orígenes permitidos.
 * Métodos específicos: Permite el acceso solo a ciertos métodos desde los
 * orígenes permitidos.
 */
@CrossOrigin(origins = { "http://localhost:4200" }, originPatterns = "*")
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService service;

    @GetMapping
    public List<User> list() {
        return service.findAll();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody User user, BindingResult result) {
        if (result.hasFieldErrors()) {
            return validation(result);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(service.save(user));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody User user, BindingResult result) {
        user.setAdmin(false);
        return create(user, result);
    }

    private ResponseEntity<?> validation(BindingResult result) {
        Map<String, String> errors = new HashMap<>();

        result.getFieldErrors().forEach(err -> {
            errors.put(err.getField(), "El campo " + err.getField() + " " + err.getDefaultMessage());
        });

        return ResponseEntity.badRequest().body(errors);
    }
}
