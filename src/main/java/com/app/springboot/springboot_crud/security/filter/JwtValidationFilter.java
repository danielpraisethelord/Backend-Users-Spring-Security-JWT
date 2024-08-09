package com.app.springboot.springboot_crud.security.filter;

import static com.app.springboot.springboot_crud.security.TokenJwtConfig.CONTENT_TYPE;
import static com.app.springboot.springboot_crud.security.TokenJwtConfig.HEADER_AUTHORIZATION;
import static com.app.springboot.springboot_crud.security.TokenJwtConfig.PREFIX_TOKEN;
import static com.app.springboot.springboot_crud.security.TokenJwtConfig.SECRET_KEY;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.app.springboot.springboot_crud.security.SimpleGrantedAuthorityJsonCreator;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Extender de la clase BasicAuthenticationFilter en Spring Security te permite
 * personalizar el proceso de autenticación HTTP Basic.
 * BasicAuthenticationFilter es un filtro de seguridad que intercepta las
 * solicitudes HTTP y verifica las credenciales proporcionadas en el encabezado
 * Authorization de la solicitud para autenticar al usuario.
 * 
 * Propósito de BasicAuthenticationFilter
 * BasicAuthenticationFilter se encarga de:
 * 
 * Intercepción de Solicitudes: Intercepta todas las solicitudes HTTP antes de
 * que lleguen a los controladores.
 * Extracción de Credenciales: Extrae las credenciales (nombre de usuario y
 * contraseña) del encabezado Authorization.
 * Autenticación de Usuarios: Autentica al usuario utilizando un
 * AuthenticationManager.
 * Gestión de Sesiones: Puede integrarse con la gestión de sesiones para
 * mantener al usuario autenticado en varias solicitudes.
 * Personalización mediante la Extensión de BasicAuthenticationFilter
 * Al extender BasicAuthenticationFilter, puedes personalizar o agregar
 * funcionalidades al proceso de autenticación HTTP Basic. Por ejemplo, puedes
 * agregar validaciones adicionales, manejar errores de autenticación de manera
 * específica, o integrar con otros sistemas de autenticación.
 */
public class JwtValidationFilter extends BasicAuthenticationFilter {

    /*
     * JwtValidationFilter(AuthenticationManager authenticationManager): El
     * constructor toma un AuthenticationManager como parámetro y lo pasa al
     * constructor de la clase base BasicAuthenticationFilter
     */
    public JwtValidationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /*
     * Este método se sobrescribe para proporcionar la lógica de filtrado
     * personalizada. Se ejecuta para cada solicitud HTTP interceptada por el
     * filtro.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        /*
         * request.getHeader(HEADER_AUTHORIZATION): Obtiene el valor del encabezado
         * Authorization de la solicitud HTTP.
         */
        String header = request.getHeader(HEADER_AUTHORIZATION);
        if (header == null || !header.startsWith(PREFIX_TOKEN)) {
            /*
             * return: Si la condición se cumple, la solicitud no contiene un token JWT
             * válido y el filtro no hace nada, simplemente devuelve la ejecución a la
             * cadena de filtros (chain).
             */
            chain.doFilter(request, response);
            return;
        }

        /*
         * header.replace(PREFIX_TOKEN, ""): Elimina el prefijo del token para obtener
         * el token JWT real.
         */
        String token = header.replace(PREFIX_TOKEN, "");

        try {
            /*
             * Jwts.parser().verifyWith(SECRET_KEY).build().parseSignedClaims(token).
             * getPayload():
             * 
             * Jwts.parser(): Crea un parser para el token JWT.
             * verifyWith(SECRET_KEY): Configura la clave secreta para verificar la firma
             * del token.
             * build().parseSignedClaims(token): Verifica y parsea el token, obteniendo los
             * Claims.
             * claims.getPayload(): Obtiene el contenido del token JWT.
             */
            Claims claims = Jwts.parser().verifyWith(SECRET_KEY).build().parseSignedClaims(token).getPayload();
            /*
             * Obtiene el nombre de usuario del campo subject en los claims del token.
             */
            String username = claims.getSubject();
            // String username2 = (String) claims.get("username");
            Object authoritiesClaims = claims.get("authorities");

            /*
             * new ObjectMapper(): Crea un nuevo ObjectMapper de Jackson para convertir
             * JSON.
             * .addMixIn(SimpleGrantedAuthority.class,
             * SimpleGrantedAuthorityJsonCreator.class): Añade una mezcla (mixin) para
             * personalizar la deserialización de SimpleGrantedAuthority.
             * .readValue(authoritiesClaims.toString().getBytes(),
             * SimpleGrantedAuthority[].class): Convierte los claims de authorities a una
             * colección de SimpleGrantedAuthority.
             */
            Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
                    .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityJsonCreator.class)
                    .readValue(authoritiesClaims.toString().getBytes(), SimpleGrantedAuthority[].class));

            /*
             * new UsernamePasswordAuthenticationToken(username, null, authorities): Crea un
             * token de autenticación con el nombre de usuario y las autoridades (roles).
             * SecurityContextHolder.getContext().setAuthentication(authenticationToken):
             * Establece el contexto de seguridad con el token de autenticación.
             * chain.doFilter(request, response): Continúa con la cadena de filtros,
             * permitiendo que la solicitud proceda.
             */
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,
                    null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            chain.doFilter(request, response);
        } catch (JwtException e) {
            /*
             * catch (JwtException e): Atrapa cualquier excepción relacionada con JWT, lo
             * que indica que el token es inválido.
             * Map<String, String> body = new HashMap<>();: Crea un mapa para el cuerpo de
             * la respuesta de error.
             * body.put("error", e.getMessage());: Añade el mensaje de error al cuerpo de la
             * respuesta.
             * body.put("message", "El token Jwt es invalido!");: Añade un mensaje adicional
             * indicando que el token es inválido.
             * response.getWriter().write(new ObjectMapper().writeValueAsString(body));:
             * Convierte el cuerpo del mensaje a JSON y lo escribe en la respuesta.
             * response.setStatus(HttpStatus.UNAUTHORIZED.value());: Establece el código de
             * estado HTTP a 401 Unauthorized.
             * response.setContentType(CONTENT_TYPE);: Establece el tipo de contenido de la
             * respuesta a JSON.
             */
            Map<String, String> body = new HashMap<>();
            body.put("error", e.getMessage());
            body.put("message", "El token Jwt es invalido!");

            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(CONTENT_TYPE);
        }

    }

}
