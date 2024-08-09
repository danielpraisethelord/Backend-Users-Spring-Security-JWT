package com.app.springboot.springboot_crud.security.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Collection;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.app.springboot.springboot_crud.entities.User;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static com.app.springboot.springboot_crud.security.TokenJwtConfig.*;

/**
 * La clase UsernamePasswordAuthenticationFilter es una parte fundamental del
 * framework de seguridad de Spring Security. Esta clase es responsable de
 * gestionar el proceso de autenticación basado en el nombre de usuario y la
 * contraseña.
 * 
 * Propósito
 * UsernamePasswordAuthenticationFilter se utiliza para autenticar las
 * credenciales de un usuario (nombre de usuario y contraseña) en aplicaciones
 * web. Su propósito principal es interceptar las solicitudes de autenticación,
 * extraer las credenciales proporcionadas por el usuario, y delegar la
 * autenticación a un AuthenticationManager.
 * 
 * Funcionamiento
 * Interceptar Solicitudes:
 * El filtro intercepta las solicitudes HTTP (generalmente solicitudes POST)
 * enviadas al punto de acceso de autenticación (por defecto /login).
 * 
 * Extraer Credenciales:
 * Extrae el nombre de usuario y la contraseña de la solicitud. Por defecto,
 * espera que estos parámetros se llamen username y password, respectivamente.
 * Sin embargo, estos nombres pueden configurarse según las necesidades.
 * 
 * Crear un Token de Autenticación:
 * Con las credenciales extraídas, el filtro crea una instancia de
 * UsernamePasswordAuthenticationToken, que es una implementación de
 * Authentication que contiene las credenciales del usuario.
 * 
 * Delegar la Autenticación:
 * El token de autenticación se pasa al AuthenticationManager configurado, que
 * se encarga de autenticar al usuario. El AuthenticationManager suele estar
 * configurado con un UserDetailsService y un PasswordEncoder para verificar las
 * credenciales.
 * 
 * Gestionar el Resultado de la Autenticación:
 * 
 * Éxito: Si la autenticación es exitosa, el filtro llama a un
 * AuthenticationSuccessHandler (por defecto,
 * SavedRequestAwareAuthenticationSuccessHandler), que redirige al usuario a la
 * página solicitada originalmente o a una página de inicio configurada.
 * Fallo: Si la autenticación falla, el filtro llama a un
 * AuthenticationFailureHandler (por defecto,
 * SimpleUrlAuthenticationFailureHandler), que redirige al usuario a la página
 * de inicio de sesión con un mensaje de error.
 * 
 * 
 */
public class JwtAutheticationFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * AuthenticationManager es una interfaz central en Spring Security responsable
     * de gestionar el proceso de autenticación de usuarios.
     * Propósito
     * El AuthenticationManager se encarga de autenticar una solicitud de
     * autenticación. Toma un objeto de autenticación (por ejemplo,
     * UsernamePasswordAuthenticationToken) que contiene las credenciales del
     * usuario y devuelve un objeto de autenticación completamente autenticado, si
     * las credenciales son válidas.
     * 
     * Funcionamiento
     * Recibir la Solicitud de Autenticación:
     * 
     * El AuthenticationManager recibe un objeto de autenticación, que contiene las
     * credenciales del usuario (como nombre de usuario y contraseña).
     * Delegar la Autenticación:
     * 
     * El AuthenticationManager delega el proceso de autenticación a uno o más
     * AuthenticationProvider configurados. Cada AuthenticationProvider intenta
     * autenticar las credenciales proporcionadas.
     * Resultado de la Autenticación:
     * 
     * Si alguna de las AuthenticationProvider autenticaciones con éxito, el
     * AuthenticationManager devuelve un objeto de autenticación completamente
     * autenticado (por ejemplo, con detalles de usuario y roles/autoridades).
     * Si ninguna AuthenticationProvider puede autenticar la solicitud, se lanza una
     * excepción de autenticación (como BadCredentialsException).
     */
    private AuthenticationManager authenticationManager;

    public JwtAutheticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        User user = null;
        String username = null;
        String password = null;

        /*
         * ObjectMapper es una clase fundamental en la biblioteca Jackson (parte de
         * FasterXML) utilizada para la serialización y deserialización de objetos Java
         * a y desde JSON.
         * 
         * Propósito
         * ObjectMapper se utiliza para convertir objetos Java en su representación JSON
         * (serialización) y para convertir JSON en objetos Java (deserialización). Es
         * una herramienta muy poderosa y flexible que facilita trabajar con JSON en
         * aplicaciones Java.
         */
        try {
            user = new ObjectMapper().readValue(request.getInputStream(), User.class);
            username = user.getUsername();
            password = user.getPassword();
        } catch (StreamReadException e) {
            e.printStackTrace();
        } catch (DatabindException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        /*
         * UsernamePasswordAuthenticationToken es una clase en Spring Security que
         * implementa la interfaz Authentication. Se utiliza para representar las
         * credenciales de autenticación basadas en el nombre de usuario y la contraseña
         * El propósito principal de UsernamePasswordAuthenticationToken es almacenar
         * las credenciales del usuario (nombre de usuario y contraseña) durante el
         * proceso de autenticación. Se usa tanto para las solicitudes de autenticación
         * entrantes como para las representaciones de autenticación autenticadas.
         * 
         * Funcionamiento
         * Creación del Token:
         * 
         * Cuando un usuario intenta autenticarse proporcionando un nombre de usuario y
         * una contraseña, se crea una instancia de UsernamePasswordAuthenticationToken
         * con estas credenciales.
         * Durante la creación inicial, el token contiene el nombre de usuario y la
         * contraseña no cifrada.
         * Proceso de Autenticación:
         * 
         * El AuthenticationManager utiliza este token para autenticar al usuario. Se
         * pasa a un AuthenticationProvider, que verifica las credenciales.
         * Si la autenticación es exitosa, se crea un nuevo
         * UsernamePasswordAuthenticationToken, esta vez con los detalles del usuario
         * autenticado y las autoridades (roles/privilegios) del usuario.
         * Estados del Token:
         * 
         * Antes de la Autenticación: Contiene solo el nombre de usuario y la
         * contraseña.
         * Después de la Autenticación: Contiene los detalles del usuario autenticado y
         * sus autoridades. En este estado, las credenciales (contraseña) usualmente se
         * eliminan por razones de seguridad.
         */
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,
                password);

        return authenticationManager.authenticate(authenticationToken);
    }

    /*
     * Se llama cuando una autenticación ha sido exitosa y su propósito es generar
     * un JSON Web Token (JWT) para el usuario autenticado, agregarlo a la respuesta
     * HTTP, y devolver información adicional al cliente.
     * 
     * Parámetros:
     * HttpServletRequest request: La solicitud HTTP.
     * HttpServletResponse response: La respuesta HTTP.
     * FilterChain chain: La cadena de filtros que se procesarán después de este
     * filtro.
     * Authentication authResult: El resultado de la autenticación que contiene
     * información del usuario autenticado.
     * 
     * Este método se encarga de:
     * 
     * Obtener la información del usuario autenticado.
     * Generar un JWT con el nombre de usuario como sujeto.
     * Agregar el token JWT a la respuesta HTTP en el encabezado Authorization.
     * Construir un cuerpo de respuesta JSON que incluye el token, el nombre de
     * usuario y un mensaje de éxito.
     * Enviar la respuesta JSON al cliente con un código de estado 200 (OK).
     * En un contexto de autenticación, este método permite a la aplicación emitir
     * un token JWT a un usuario autenticado, que luego puede ser utilizado por el
     * cliente para autenticar solicitudes subsecuentes al servidor.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {

        /*
         * authResult.getPrincipal(): Obtiene el principal autenticado (el usuario).
         * Cast a SecurityProperties.User: Convierte el principal a la clase
         * SecurityProperties.User de Spring Boot.
         * user.getName(): Obtiene el nombre de usuario del objeto User.
         */
        org.springframework.security.core.userdetails.User user = (org.springframework.security.core.userdetails.User) authResult
                .getPrincipal();
        String username = user.getUsername();
        /*
         * authResult.getAuthorities():
         * authResult es una instancia de Authentication que contiene el resultado de la
         * autenticación.
         * El método getAuthorities() devuelve una colección de GrantedAuthority que
         * representa las autoridades (roles/privilegios) otorgadas al usuario
         * autenticado.
         * Collection<? extends GrantedAuthority>:
         * Collection es una interfaz de la colección de Java que permite almacenar un
         * grupo de objetos.
         * <? extends GrantedAuthority> es una declaración genérica que indica que la
         * colección puede contener cualquier tipo que extienda GrantedAuthority.
         * GrantedAuthority es una interfaz de Spring Security que representa una
         * autoridad otorgada a un objeto de autenticación.
         */
        Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

        /*
         * Jwts.claims().build();:
         * 
         * Jwts.claims() crea una instancia de Claims, que es una interfaz proporcionada
         * por la biblioteca JWT para representar las reclamaciones en un JWT.
         * build() completa la construcción del objeto Claims.
         * claims.put("authorities", roles);:
         * 
         * claims.put(...) agrega una nueva reclamación al objeto Claims.
         * "authorities" es la clave de la reclamación que se agregará. Es una cadena
         * que identifica el tipo de dato que se está almacenando.
         * roles es el valor de la reclamación. En este caso, es la colección de
         * autoridades (roles/privilegios) del usuario autenticado.
         */
        Claims claims = Jwts.claims()
                .add("authorities", new ObjectMapper().writeValueAsString(roles))
                .add("username", username)
                .build();

        /*
         * Jwts.builder(): Inicia la construcción del JWT.
         * .setSubject(username): Establece el nombre de usuario como el sujeto del
         * token.
         * .claims(claims): incluye las autoridades del usuario autenticado dentro del
         * JWT.
         * .expiration(new Date(..)): La expiración es de la fecha actual mas una hora
         * en milisegundos
         * .issuedAt(new Date()): Es la fecha cuando se creo el Token
         * .signWith(SECRET_KEY): Firma el token con la clave secreta SECRET_KEY.
         * .compact(): Construye y serializa el token en una cadena compacta.
         */
        String token = Jwts.builder()
                .subject(username)
                .claims(claims)
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .issuedAt(new Date())
                .signWith(SECRET_KEY)
                .compact();

        /*
         * response.addHeader("Authorization", "Bearer " + token): Agrega un encabezado
         * Authorization a la respuesta HTTP con el token en formato Bearer.
         */
        response.addHeader(HEADER_AUTHORIZATION, PREFIX_TOKEN + token);
        Map<String, String> body = new HashMap<>();
        body.put("token", token);
        body.put("username", username);
        body.put("message", String.format("Hola %s has iniciado sesión con éxito", username));

        /*
         * response.getWriter().write(...): Escribe el cuerpo de la respuesta como JSON
         * utilizando ObjectMapper para serializar el mapa.
         * response.setContentType("application/json"): Establece el tipo de contenido
         * de la respuesta como application/json.
         * response.setStatus(200): Establece el código de estado de la respuesta a 200
         * (OK).
         */
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setContentType(CONTENT_TYPE);
        response.setStatus(200);
    }

    /**
     * unsuccessfulAuthentication se llama cuando una autenticación no tiene éxito
     * en una implementación personalizada de UsernamePasswordAuthenticationFilter.
     * Su propósito es manejar los errores de autenticación y enviar una respuesta
     * adecuada al cliente, informando sobre la falla.
     * 
     * Parámetros:
     * HttpServletRequest request: La solicitud HTTP que intentó autenticarse.
     * HttpServletResponse response: La respuesta HTTP que se enviará al cliente.
     * AuthenticationException failed: La excepción que fue lanzada durante el
     * proceso de autenticación, proporcionando información sobre por qué falló la
     * autenticación.
     * 
     * Este método unsuccessfulAuthentication realiza los siguientes pasos cuando la
     * autenticación falla:
     * 
     * Crea un mapa para almacenar los detalles del error.
     * Agrega un mensaje general sobre el error de autenticación y el mensaje
     * específico de la excepción al mapa.
     * Convierte el mapa en JSON y lo escribe en el cuerpo de la respuesta HTTP.
     * Establece el código de estado de la respuesta a 401 Unauthorized.
     * Configura el tipo de contenido de la respuesta como application/json.
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {

        Map<String, String> body = new HashMap<>();
        body.put("Message", "Error en la autenticación, username o password incorrectos!");
        body.put("error", failed.getMessage());

        /*
         * response.getWriter().write(new ObjectMapper().writeValueAsString(body));:
         * 
         * Utiliza un ObjectMapper de Jackson para convertir el mapa body en una cadena
         * JSON y escribe esta cadena en el cuerpo de la respuesta HTTP.
         * response.setStatus(HttpStatus.UNAUTHORIZED.value());:
         * 
         * Establece el código de estado de la respuesta HTTP a 401 Unauthorized,
         * indicando que la solicitud de autenticación no fue exitosa.
         * response.setContentType(CONTENT_TYPE);:
         * 
         * Establece el tipo de contenido de la respuesta HTTP. CONTENT_TYPE es
         * una constante que define el tipo de contenido,
         * "application/json".
         */
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(CONTENT_TYPE);
    }
}
