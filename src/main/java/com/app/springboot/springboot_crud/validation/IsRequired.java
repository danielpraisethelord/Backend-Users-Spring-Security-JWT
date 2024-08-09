package com.app.springboot.springboot_crud.validation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Constraint(validatedBy = RequiredValidation.class)
/**
 * Claro, la anotación Retention en Java es parte del paquete
 * java.lang.annotation y se utiliza para especificar cuánto tiempo debe
 * conservarse una anotación. En otras palabras, define la visibilidad de una
 * anotación a lo largo del ciclo de vida del programa.
 * 
 * El valor de la anotación Retention debe ser uno de los elementos de la
 * enumeración RetentionPolicy, que define tres posibles políticas de retención:
 * 
 * RetentionPolicy.SOURCE: La anotación se conserva solo en el código fuente y
 * se descarta durante la compilación. No estará presente en los archivos .class
 * ni en tiempo de ejecución.
 * 
 * RetentionPolicy.CLASS: La anotación se conserva en los archivos .class
 * durante la compilación, pero no está disponible en tiempo de ejecución. Este
 * es el valor predeterminado si no se especifica ninguna política de retención.
 * 
 * RetentionPolicy.RUNTIME: La anotación se conserva en los archivos .class y
 * está disponible en tiempo de ejecución a través de la reflexión (reflection).
 * Esto es útil si necesitas inspeccionar anotaciones durante la ejecución del
 * programa.
 */
@Retention(RetentionPolicy.RUNTIME)
/*
 * La anotación Target en Java se utiliza para especificar los elementos del
 * programa a los que se puede aplicar una anotación. Es parte del paquete
 * java.lang.annotation y ayuda a restringir el uso de una anotación solo a
 * ciertos contextos, como clases, métodos, campos, etc.
 * 
 * La enumeración ElementType define los diferentes tipos de elementos del
 * programa que se pueden anotar. Los valores más comunes de ElementType
 * incluyen:
 * 
 * ElementType.TYPE: Clase, interfaz (incluidas las interfaces anotadas), o
 * enumeración
 * 
 * ElementType.FIELD: Campo (incluidas las constantes enum).
 * 
 * ElementType.METHOD: Método.
 * 
 * ElementType.PARAMETER: Parámetro de un método.
 * 
 * ElementType.CONSTRUCTOR: Constructor.
 * 
 * ElementType.LOCAL_VARIABLE: Variable local.
 * 
 * ElementType.ANNOTATION_TYPE: Otra anotación.
 * 
 * ElementType.PACKAGE: Paquete.
 */
@Target({ ElementType.FIELD, ElementType.METHOD })
public @interface IsRequired {

    /*
     * Propósito: Este elemento define el mensaje de error predeterminado que se
     * mostrará si la validación falla.
     * Uso: Permite personalizar el mensaje de error. En el contexto de
     * validaciones, cuando un campo anotado con @IsRequired no cumple con la
     * validación, este mensaje se puede utilizar para proporcionar información al
     * usuario.
     */
    String message() default "Es requerido! (Usando anotaciones)";

    /*
     * Propósito: Este elemento se utiliza para especificar grupos de validación.
     * Los grupos permiten agrupar diferentes reglas de validación y aplicar
     * diferentes conjuntos de validaciones en diferentes contextos.
     * Uso: En un entorno de validación, puedes definir varios grupos y aplicar
     * ciertas validaciones solo a ciertos grupos. Esto es útil en formularios
     * complejos donde diferentes partes del formulario pueden requerir diferentes
     * validaciones.
     */
    Class<?>[] groups() default {};

    /*
     * Propósito: Este elemento se utiliza para llevar información adicional sobre
     * la violación de la restricción. Generalmente, se utiliza para transportar
     * metadatos sobre la restricción.
     * Uso: Es menos común en validaciones simples y se usa principalmente en
     * validaciones más avanzadas, donde necesitas adjuntar información adicional a
     * una restricción.
     * Ejemplo de uso: Aunque en la mayoría de los casos no se utiliza directamente
     * en código de usuario, puede ser útil para integrar con sistemas que procesan
     * y manejan las violaciones de restricciones de manera personalizada.
     */
    Class<? extends Payload>[] payload() default {};
}
