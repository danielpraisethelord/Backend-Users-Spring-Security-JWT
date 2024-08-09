package com.app.springboot.springboot_crud.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.app.springboot.springboot_crud.security.filter.JwtAutheticationFilter;
import com.app.springboot.springboot_crud.security.filter.JwtValidationFilter;

@Configuration
/*
 * La anotación @EnableWebSecurity en Spring Security se utiliza para habilitar
 * la configuración de seguridad web en una aplicación Spring. Cuando se aplica,
 * esta anotación configura una clase para ser el punto central de la
 * configuración de seguridad de la aplicación, permitiéndote personalizar cómo
 * se manejan las solicitudes HTTP y cómo se protegen las rutas específicas de
 * tu aplicación web.
 * 
 * Propósito de @EnableWebSecurity
 * El propósito principal de @EnableWebSecurity es habilitar la configuración de
 * seguridad web, permitiéndote definir políticas de seguridad, como la
 * autenticación y autorización, para tu aplicación web. Sin esta anotación, las
 * configuraciones de seguridad web personalizadas no se aplicarían.
 * 
 * Uso de @EnableWebSecurity
 * La anotación @EnableWebSecurity se aplica a una clase que extiende
 * WebSecurityConfigurerAdapter (antes de Spring Security 5.7) o implementa
 * SecurityConfigurer (a partir de Spring Security 5.7). Aquí tienes un ejemplo
 * de cómo usarla:
 */
// @EnableWebSecurity
/*
 * La anotación @EnableMethodSecurity en Spring Security (anteriormente conocida
 * como @EnableGlobalMethodSecurity) se utiliza para habilitar la seguridad a
 * nivel de métodos en una aplicación Spring. Esta anotación permite que las
 * anotaciones de seguridad, como @PreAuthorize, @PostAuthorize, @Secured,
 * y @RolesAllowed, sean aplicables a los métodos de tus beans administrados por
 * Spring.
 * 
 * Propósito de @EnableMethodSecurity
 * El propósito principal de @EnableMethodSecurity es proporcionar una capa
 * adicional de seguridad al nivel de métodos. Esto significa que puedes
 * proteger métodos específicos en tus servicios, controladores, o repositorios,
 * y no solo URLs específicas en tu aplicación.
 */
@EnableMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfig {

    /*
     * El AuthenticationManager es un componente central de Spring Security que se
     * utiliza para manejar la autenticación. Es responsable de autenticar las
     * credenciales del usuario (como el nombre de usuario y la contraseña).
     * Inyección de AuthenticationConfiguration:
     * 
     * Se inyecta AuthenticationConfiguration para poder acceder a las
     * configuraciones de autenticación definidas en tu aplicación.
     * Definición de un Bean de AuthenticationManager:
     * 
     * Se define un método anotado con @Bean que retorna una instancia de
     * AuthenticationManager. Esto hace que el AuthenticationManager esté disponible
     * como un bean en el contexto de Spring.
     * El método utiliza authenticationConfiguration.getAuthenticationManager() para
     * obtener la instancia configurada del AuthenticationManager.
     */
    /*
     * Aquí se inyecta una instancia de AuthenticationConfiguration.
     * AuthenticationConfiguration es una clase de Spring Security que proporciona
     * acceso al AuthenticationManager configurado en la aplicación.
     * Esta clase permite obtener configuraciones de autenticación personalizadas.
     */
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    /*
     * @Bean:
     * 
     * La anotación @Bean indica que el método produce un bean que será manejado por
     * el contenedor de Spring. Este bean se registrará en el contexto de aplicación
     * de Spring.
     * AuthenticationManager authenticationManager() throws Exception:
     * 
     * Este método define un bean del tipo AuthenticationManager.
     * return authenticationConfiguration.getAuthenticationManager();:
     * 
     * Aquí se llama al método getAuthenticationManager() del objeto
     * authenticationConfiguration inyectado.
     * getAuthenticationManager() devuelve la instancia de AuthenticationManager que
     * ha sido configurada en la aplicación.
     */
    @Bean
    AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /*
     * 1. @Bean
     * La anotación @Bean es parte del framework Spring y se utiliza en un método
     * para indicar que el resultado de ese método debe ser registrado como un bean
     * en el contexto de la aplicación Spring. Un bean en Spring es un objeto que se
     * instancia, ensamblaje y se gestiona completamente por el contenedor de
     * Spring.
     * 
     * En este caso, el método passwordEncoder() devuelve un bean de tipo
     * PasswordEncoder.
     * 
     * 2. PasswordEncoder
     * PasswordEncoder es una interfaz en Spring Security que define métodos para
     * codificar y verificar contraseñas. Los dos métodos principales son:
     * 
     * String encode(CharSequence rawPassword): Codifica la contraseña en texto
     * plano.
     * boolean matches(CharSequence rawPassword, String encodedPassword): Verifica
     * si la contraseña en texto plano coincide con la contraseña codificada.
     * 3. new BCryptPasswordEncoder()
     * BCryptPasswordEncoder es una implementación de PasswordEncoder que utiliza el
     * algoritmo BCrypt para codificar contraseñas. BCrypt es un algoritmo de
     * hashing adaptativo que es muy recomendado para almacenar contraseñas debido a
     * su resistencia a los ataques de fuerza bruta.
     * 
     * Contexto de Uso
     * Este bean se utiliza típicamente en aplicaciones que requieren seguridad,
     * como aquellas que gestionan autenticación de usuarios.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
     * Qué es SecurityFilterChain?
     * SecurityFilterChain es una interfaz de Spring Security que define una cadena
     * de filtros (filters) a través de los cuales pasan todas las solicitudes HTTP.
     * Estos filtros se utilizan para aplicar diversas medidas de seguridad, como
     * autenticación, autorización, manejo de sesiones, protección CSRF, etc.
     * 
     * ¿Qué hace el método filterChain?
     * El método filterChain configura esta cadena de filtros usando el objeto
     * HttpSecurity, que es una clase de configuración que permite personalizar el
     * comportamiento de seguridad de la aplicación.
     * 
     * 1. @Bean
     * La anotación @Bean indica que este método produce un bean que se gestionará
     * por el contenedor de Spring. En este caso, el bean es una instancia de
     * SecurityFilterChain.
     * 
     * 2. Configuración de HttpSecurity
     * El objeto HttpSecurity se utiliza para configurar la seguridad HTTP para tu
     * aplicación web.
     * 
     * a. authorizeHttpRequests
     * Configura las reglas de autorización para las solicitudes HTTP.
     * 
     * requestMatchers("/users").permitAll(): Permite que cualquier persona acceda a
     * la URL /users sin necesidad de autenticación.
     * anyRequest().authenticated(): Requiere que cualquier otra solicitud esté
     * autenticada.
     * 
     * b. csrf(config -> config.disable())
     * Desactiva la protección CSRF (Cross-Site Request Forgery).
     * 
     * Desactivar CSRF puede ser apropiado en aplicaciones que no usan formularios
     * web tradicionales, como servicios RESTful que manejan autenticación y
     * autorización a través de tokens.
     * c. sessionManagement
     * Configura la política de manejo de sesiones.
     * 
     * sessionCreationPolicy(SessionCreationPolicy.STATELESS): Configura la
     * aplicación para no utilizar sesiones HTTP para mantener el estado de
     * autenticación. Esto es común en aplicaciones RESTful que utilizan tokens
     * (como JWT) para autenticación y autorización.
     * d. build()
     * Construye y devuelve la configuración de seguridad definida.
     * 
     * Este método de configuración:
     * 
     * Define una política de autorización donde la URL /users es accesible para
     * todos, pero cualquier otra URL requiere autenticación.
     * Desactiva la protección CSRF, que es adecuada para aplicaciones sin sesiones
     * basadas en formularios (como APIs REST).
     * Configura la aplicación para ser "stateless" en términos de manejo de
     * sesiones, lo cual es típico para servicios REST que usan tokens para
     * autenticación en lugar de sesiones de usuario tradicionales.
     * Al configurar un SecurityFilterChain de esta manera, se personaliza cómo se
     * maneja la seguridad en tu aplicación Spring, asegurando que solo los usuarios
     * autenticados puedan acceder a la mayoría de los recursos y que se utilicen
     * prácticas seguras adecuadas para APIs RESTful.
     */
    /**
     * Configura la cadena de filtros de seguridad para la aplicación.
     *
     * @param http el objeto HttpSecurity que se utiliza para configurar la
     *             seguridad HTTP.
     * @return una instancia de SecurityFilterChain que contiene la configuración de
     *         seguridad.
     * @throws Exception si ocurre algún error durante la configuración de
     *                   seguridad.
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(authz -> authz
                // Permite todas las solicitudes GET a la ruta "/api/users" sin autenticación
                .requestMatchers(HttpMethod.GET, "/api/users").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/users/register").permitAll()
                // Permite todas las solicitudes POST a la ruta "/api/users/register" sin
                // autenticación
                // .requestMatchers(HttpMethod.POST, "/api/users/register").permitAll()
                // .requestMatchers(HttpMethod.POST, "/api/users").hasRole("ADMIN")
                // .requestMatchers(HttpMethod.POST, "/api/products").hasRole("ADMIN")
                // .requestMatchers(HttpMethod.GET, "/api/products",
                // "/api/products/{id}").hasAnyRole("ADMIN", "USER")
                // .requestMatchers(HttpMethod.PUT, "/api/products/{id}").hasRole("ADMIN")
                // .requestMatchers(HttpMethod.DELETE, "/api/products/{id}").hasRole("ADMIN")
                // Requiere autenticación para cualquier otra solicitud
                .anyRequest().authenticated())
                // Añadimos el filtro de seguridad creado
                .addFilter(new JwtAutheticationFilter(authenticationManager()))
                .addFilter(new JwtValidationFilter(authenticationManager()))
                // Desactiva la protección CSRF
                .csrf(config -> config.disable())
                .cors(cors -> cors.configurationSource(configurationSource()))
                // Configura la sesión para ser STATELESS, es decir, sin estado de sesión
                .sessionManagement(managment -> managment.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Construye la configuración de seguridad
                .build();
    }

    /*
     * La interfaz CorsConfigurationSource en Spring Security es parte del sistema
     * de configuración de CORS (Cross-Origin Resource Sharing) y se utiliza para
     * definir cómo se deben configurar las políticas CORS para las solicitudes
     * entrantes. Esta interfaz proporciona una manera de suministrar instancias de
     * CorsConfiguration, que definen las reglas CORS para las solicitudes que
     * coinciden con un determinado origen, ruta o método HTTP.
     * 
     * Propósito de CorsConfigurationSource
     * El propósito principal de la interfaz CorsConfigurationSource es permitir que
     * una aplicación Spring Security proporcione configuraciones CORS
     * personalizadas para cada solicitud entrante. Esto es útil cuando deseas
     * aplicar reglas CORS más sofisticadas o específicas en tu aplicación, en lugar
     * de utilizar las configuraciones predeterminadas.
     * 
     * Funcionamiento de CorsConfigurationSource
     * Cuando se recibe una solicitud HTTP, Spring Security verifica si la solicitud
     * debe ser tratada como una solicitud CORS. Si es así, utiliza una instancia de
     * CorsConfigurationSource para obtener la configuración CORS adecuada para esa
     * solicitud.
     * 
     * Este método configura cómo la aplicación Spring manejará las solicitudes HTTP
     * de diferentes orígenes (dominios). Con esta configuración:
     * 
     * Todos los orígenes están permitidos.
     * Los métodos HTTP permitidos son GET, POST, DELETE, y PUT.
     * Los encabezados permitidos incluyen Authorization y Content-Type.
     * Las credenciales como cookies o encabezados de autenticación están
     * permitidas.
     * La configuración se aplica a todas las rutas de la aplicación (/**).
     * Esta configuración es útil para permitir que una aplicación frontend (como
     * una aplicación Angular, React, etc.) que esté alojada en un dominio diferente
     * pueda interactuar con el backend Spring Boot de manera segura y controlada.
     */
    @Bean
    CorsConfigurationSource configurationSource() {
        /*
         * Se crea una nueva instancia de CorsConfiguration, que es la clase utilizada
         * para definir las reglas y políticas CORS que se aplicarán.
         * 
         */
        CorsConfiguration config = new CorsConfiguration();
        /*
         * setAllowedOriginPatterns: Permite especificar patrones de origen que están
         * permitidos para acceder a los recursos de la aplicación. Aquí, * significa
         * que se permiten todos los orígenes (es decir, cualquier dominio puede hacer
         * solicitudes a la aplicación).
         * Es importante notar que setAllowedOriginPatterns es más flexible que
         * setAllowedOrigins, ya que permite el uso de patrones, como * para permitir
         * todos los orígenes, o http://*.example.com para permitir subdominios
         * específicos.
         */
        config.setAllowedOriginPatterns(Arrays.asList("*"));
        /*
         * setAllowedMethods: Especifica qué métodos HTTP están permitidos en las
         * solicitudes CORS. En este caso, se permiten los métodos GET, POST, DELETE, y
         * PUT.
         */
        config.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT"));
        /*
         * setAllowedHeaders: Define qué encabezados HTTP pueden ser incluidos en las
         * solicitudes. Aquí se permiten los encabezados Authorization (usualmente para
         * enviar tokens de autenticación) y Content-Type (para especificar el tipo de
         * contenido de la solicitud).
         */
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        /*
         * setAllowCredentials(true): Indica que las solicitudes pueden incluir
         * credenciales, como cookies o encabezados de autenticación. Esto es importante
         * cuando se necesita que las solicitudes mantengan el estado de autenticación
         * (por ejemplo, cuando se gestionan sesiones).
         */
        config.setAllowCredentials(true);
        /*
         * Se crea una instancia de UrlBasedCorsConfigurationSource, que es una
         * implementación de CorsConfigurationSource que permite asociar configuraciones
         * CORS con patrones de URL específicos.
         * registerCorsConfiguration("/**", config): Registra la configuración CORS para
         * todas las rutas (/**) de la aplicación. Esto significa que las reglas
         * definidas en config se aplicarán a todas las solicitudes que lleguen a
         * cualquier ruta de la aplicación.
         */
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    /*
     * La clase FilterRegistrationBean en Spring Framework se utiliza para registrar
     * y configurar filtros dentro de la aplicación web. Un filtro en el contexto de
     * una aplicación web es un componente que intercepta solicitudes y respuestas
     * HTTP para realizar alguna operación antes de que lleguen a un servlet o
     * después de que salgan de un servlet.
     * 
     * Propósito de FilterRegistrationBean
     * El propósito principal de FilterRegistrationBean es proporcionar una manera
     * programática y flexible de registrar filtros en una aplicación Spring Boot,
     * sin necesidad de configurarlos directamente en el archivo web.xml, como se
     * hacía tradicionalmente en aplicaciones Java EE.
     * 
     * Características Clave
     * Registro de Filtros: Permite registrar uno o más filtros en el contexto de la
     * aplicación.
     * Orden de Ejecución: Puedes especificar el orden en el que se ejecutan los
     * filtros si hay más de uno.
     * Mapeo de URLs: Te permite definir a qué URLs o patrones de URL se aplica el
     * filtro.
     * Configuración de Filtros: Permite pasar parámetros de inicialización al
     * filtro o configurar sus propiedades de manera programática.
     * 
     * Este código se utiliza para registrar un filtro de CORS (CorsFilter) en una
     * aplicación Spring Boot y asegurarse de que se ejecute con la más alta
     * prioridad. Este filtro es esencial para manejar las solicitudes CORS
     * (Cross-Origin Resource Sharing) de manera adecuada.
     */
    /*
     * FilterRegistrationBean<CorsFilter>: Es un FilterRegistrationBean
     * parametrizado para registrar un CorsFilter, que es el filtro encargado de
     * gestionar las solicitudes CORS.
     */
    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter() {
        /*
         * new FilterRegistrationBean<>(new CorsFilter(configurationSource())): Se crea
         * una nueva instancia de FilterRegistrationBean, pasando un CorsFilter como
         * argumento.
         * CorsFilter(configurationSource()): El CorsFilter se inicializa con la
         * configuración de CORS que se obtiene del método configurationSource()
         * Este método (configurationSource()) devuelve una instancia de
         * CorsConfigurationSource que define las reglas CORS.
         */
        FilterRegistrationBean<CorsFilter> corsBean = new FilterRegistrationBean<>(
                new CorsFilter(configurationSource()));
        /*
         * setOrder(Ordered.HIGHEST_PRECEDENCE): Se establece la prioridad de este
         * filtro. Ordered.HIGHEST_PRECEDENCE es una constante que asegura que este
         * filtro se ejecute antes que otros filtros. En aplicaciones Spring, los
         * filtros se ejecutan en el orden que se especifica; un valor más bajo indica
         * una prioridad más alta. Ordered.HIGHEST_PRECEDENCE asegura que este filtro
         * sea el primero en ejecutarse.
         */
        corsBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return corsBean;
    }
}