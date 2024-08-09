package com.app.springboot.springboot_crud.controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// import com.app.springboot.springboot_crud.ProductValidation;
import com.app.springboot.springboot_crud.entities.Product;
import com.app.springboot.springboot_crud.services.ProductService;

import jakarta.validation.Valid;

@CrossOrigin(origins = { "http://localhost:4200" }, originPatterns = "*")
@RestController
@RequestMapping("/api/products")
public class ProductController {

    // @Autowired
    // private ProductValidation validation;

    @Autowired
    private ProductService service;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public List<Product> list() {
        return service.findAll();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public ResponseEntity<?> view(@PathVariable Long id) {
        Optional<Product> optionalProduct = service.findById(id);
        if (optionalProduct.isPresent()) {
            return ResponseEntity.ok(optionalProduct.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }

    /*
     * En Spring Boot 3, la anotación @Valid de Jakarta se utiliza para activar la
     * validación de Java Bean en el objeto pasado como parámetro. Esta validación
     * se realiza utilizando las restricciones definidas en el objeto. La
     * anotación @Valid asegura que las propiedades del objeto cumplan con las
     * restricciones especificadas en sus anotaciones de validación
     * (como @NotNull, @Size, @Min, etc.). Si alguna de estas restricciones no se
     * cumple, se lanzará una excepción de validación (normalmente una
     * MethodArgumentNotValidException), que puede ser manejada para proporcionar
     * respuestas de error adecuadas al cliente.
     * 
     * @Valid: La anotación @Valid indica que el objeto product debe ser validado
     * antes de que el método create procese la solicitud. Las validaciones
     * aplicadas a las propiedades del Product se verificarán aquí.
     */
    /*
     * En Spring Boot 3, BindingResult es una interfaz que se utiliza para manejar y
     * contener los resultados de la validación de los datos de entrada en un
     * formulario o una solicitud HTTP. Permite acceder a los errores de validación
     * y proporciona una forma estructurada de manejar esos errores en la capa de
     * controlador.
     * 
     * ¿Qué es BindingResult?
     * BindingResult es una interfaz que forma parte del paquete
     * org.springframework.validation. Se utiliza comúnmente en métodos de
     * controladores junto con objetos de comando (o modelos) que reciben datos del
     * usuario. Su principal función es almacenar y proporcionar acceso a los
     * errores de validación.
     * 
     * ¿Para qué sirve BindingResult?
     * BindingResult sirve para:
     * 
     * Capturar Errores de Validación: Cuando se validan los datos de entrada (por
     * ejemplo, a través de anotaciones como @Valid o @Validated), BindingResult
     * captura los errores de validación. Esto permite que el desarrollador tenga
     * acceso a esos errores y pueda manejar la respuesta adecuadamente.
     * 
     * Proveer Información de Errores: Contiene detalles sobre los errores que
     * ocurrieron durante la validación, como el campo que tiene el error, el tipo
     * de error, y los mensajes de error correspondientes.
     * 
     * Control de Flujo en el Controlador: Permite a los métodos del controlador
     * decidir qué hacer en caso de que existan errores de validación. Por ejemplo,
     * puede devolver una vista con los errores, o redirigir al usuario a otra
     * página.
     * 
     * Importancia del Orden en los Parámetros del Método
     * El orden de los parámetros en los métodos del controlador es crucial cuando
     * se utiliza BindingResult. Debe seguir inmediatamente después del objeto que
     * está siendo validado. Si no se coloca en el orden correcto, Spring no será
     * capaz de asociar los errores de validación con el objeto correspondiente.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> create(@Valid @RequestBody Product product, BindingResult result) {
        // validation.validate(product, result);
        if (result.hasFieldErrors()) {
            return validation(result);
        }

        Product productNew = service.save(product);
        return ResponseEntity.status(HttpStatus.CREATED).body(productNew);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> update(@Valid @RequestBody Product product, BindingResult result,
            @PathVariable Long id) {
        // validation.validate(product, result);
        if (result.hasFieldErrors()) {
            return validation(result);
        }
        Optional<Product> productOptional = service.update(id, product);
        if (productOptional.isPresent()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(productOptional.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        Optional<Product> optionalProduct = service.delete(id);
        if (optionalProduct.isPresent()) {
            return ResponseEntity.ok(optionalProduct.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }

    private ResponseEntity<?> validation(BindingResult result) {
        Map<String, String> errors = new HashMap<>();

        result.getFieldErrors().forEach(err -> {
            errors.put(err.getField(), "El campo " + err.getField() + " " + err.getDefaultMessage());
        });

        return ResponseEntity.badRequest().body(errors);
    }

}
