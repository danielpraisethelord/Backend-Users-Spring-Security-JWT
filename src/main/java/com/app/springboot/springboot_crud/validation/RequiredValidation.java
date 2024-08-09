package com.app.springboot.springboot_crud.validation;

import org.springframework.util.StringUtils;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Implementar ConstraintValidator de jakarta.validation (anteriormente
 * javax.validation) es una parte esencial del proceso de creación de una
 * anotación de validación personalizada en Java. Esto permite definir la lógica
 * específica que determina si un valor cumple con la restricción definida por
 * la anotación. Vamos a ver en detalle para qué sirve y cómo se utiliza.
 * 
 * ¿Qué es ConstraintValidator?
 * ConstraintValidator es una interfaz genérica que proporciona la lógica para
 * validar una restricción de anotación personalizada. La interfaz está definida
 * en el paquete jakarta.validation y tiene dos parámetros genéricos:
 * 
 * A: El tipo de la anotación que define la restricción.
 * T: El tipo del elemento que se va a validar.
 */
public class RequiredValidation implements ConstraintValidator<IsRequired, String> {

    /*
     * En este método, puedes realizar cualquier configuración o inicialización
     * necesaria para la validación. Por ejemplo, podrías leer parámetros de la
     * anotación para personalizar el comportamiento de la validación.
     */
    @Override
    public void initialize(IsRequired isRequired) {
        // Puedes inicializar cualquier dato necesario aquí.
    }

    /*
     * Este método contiene la lógica que determina si el valor del campo es válido
     * o no. En este caso, simplemente verifica que el valor no sea nulo ni esté
     * vacío, ni contenga espacios en blanco
     */
    @Override
    public boolean isValid(String arg0, ConstraintValidatorContext arg1) {
        // return (arg0 != null && !arg0.isEmpty() && !arg0.isBlank());
        return StringUtils.hasText(arg0);
    }

}
