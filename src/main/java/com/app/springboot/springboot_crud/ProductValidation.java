package com.app.springboot.springboot_crud;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import com.app.springboot.springboot_crud.entities.Product;

/**
 * Extender la clase org.springframework.validation.Validator en Spring te
 * permite crear tus propios validadores personalizados para validar objetos de
 * tu aplicación de una manera que va más allá de las validaciones estándar
 * proporcionadas por las anotaciones de Bean Validation
 * (como @NotNull, @Min, @Max, etc.).
 * 
 * ¿Para qué sirve org.springframework.validation.Validator?
 * El propósito principal de implementar la interfaz Validator es proporcionar
 * una forma flexible y extensible de aplicar validaciones complejas y
 * específicas del dominio en tus objetos de datos. Esto es útil cuando las
 * validaciones no pueden ser completamente satisfechas por las anotaciones de
 * validación estándar.
 * 
 * ¿Qué es la interfaz Validator?
 * La interfaz Validator define dos métodos:
 * 
 * supports(Class<?> clazz): Este método se utiliza para indicar qué tipo de
 * objetos puede validar este validador.
 * validate(Object target, Errors errors): Este método contiene la lógica de
 * validación. El objeto a validar se pasa como el parámetro target y cualquier
 * error de validación se registra en el parámetro errors.
 */
@Component
public class ProductValidation implements Validator {

    @SuppressWarnings("null")
    @Override
    public boolean supports(Class<?> clazz) {
        return Product.class.isAssignableFrom(clazz);
    }

    /*
     * ValidationUtils es una clase de utilidad proporcionada por el framework de
     * Spring que facilita la validación de campos obligatorios (no nulos ni vacíos)
     * en tus objetos. Esta clase simplifica la validación de campos comunes al
     * proporcionar métodos convenientes que verifican si un campo está vacío o no.
     * 
     * Principales Métodos de ValidationUtils
     * Los métodos más comúnmente utilizados de ValidationUtils son:
     * 
     * rejectIfEmpty: Rechaza el valor del campo si está vacío.
     * rejectIfEmptyOrWhitespace: Rechaza el valor del campo si está vacío o
     * contiene solo espacios en blanco.
     * ¿Por qué usar ValidationUtils?
     * Usar ValidationUtils es útil porque reduce el código repetitivo al validar
     * campos obligatorios. En lugar de escribir manualmente la lógica para
     * verificar si un campo está vacío, puedes utilizar estos métodos para realizar
     * la validación de una manera más limpia y consistente.
     */
    @SuppressWarnings("null")
    @Override
    public void validate(Object target, Errors errors) {
        Product product = (Product) target;
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "name", null, "es requerido!");
        // ValidationUtils.rejectIfEmptyOrWhitespace(errors, "description",
        // "NotBlank.product.description");
        if (product.getDescription() == null || product.getDescription().isBlank()) {
            errors.rejectValue("description", null, "es requerido, por favor!");
        }

        if (product.getPrice() == null) {
            errors.rejectValue("price", null, "no puede ser nulo!");
        } else if (product.getPrice() < 10) {
            errors.rejectValue("price", null, "debe ser un valor mayor o igual que 10");
        }
    }
}
