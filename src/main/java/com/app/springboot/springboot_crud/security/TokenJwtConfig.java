package com.app.springboot.springboot_crud.security;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;

public class TokenJwtConfig {
    /*
     * Esta linea está relacionada con la generación y
     * verificación de JSON Web Tokens (JWT) utilizando una clave secreta.
     * Desglosémosla para entender mejor su propósito y funcionamiento.
     * 
     * SecretKey:
     * 
     * SecretKey es una interfaz de Java utilizada para representar claves secretas
     * en algoritmos de cifrado. En este caso, se usa para almacenar la clave
     * secreta que se utilizará para firmar y verificar los JWT.
     * Jwts.SIG.HS256.key().build();:
     * 
     * Jwts: Es una clase proporcionada por la biblioteca JWT (generalmente
     * io.jsonwebtoken.Jwts) que facilita la creación y manipulación de JWT.
     * SIG: Es un campo o método estático dentro de Jwts que probablemente agrupa
     * métodos relacionados con la firma de JWT.
     * HS256: Especifica el algoritmo de firma HMAC-SHA256. HS256 es un algoritmo de
     * hash criptográfico que se utiliza comúnmente para firmar JWT.
     * key(): Es un método que inicia el proceso de construcción de una clave
     * secreta para el algoritmo especificado (en este caso, HS256).
     * build(): Completa la construcción de la clave secreta y devuelve una
     * instancia de SecretKey.
     */
    public static final SecretKey SECRET_KEY = Jwts.SIG.HS256.key().build();

    public static final String PREFIX_TOKEN = "Bearer ";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String CONTENT_TYPE = "application/json";
}
