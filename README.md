# Documentación de Seguridad del Proyecto: Spring Boot con JWT

Este documento cubre todos los aspectos relacionados con la seguridad del proyecto, centrado en el uso de Spring Security, JWT, y varias bibliotecas clave como `jakarta`, `jsonwebtoken`, y `jackson`.

## 1. Introducción a la Seguridad en la Aplicación
El proyecto implementa una capa de seguridad que se basa en JWT (JSON Web Tokens) y Spring Security. La seguridad de la aplicación se asegura mediante la autenticación de usuarios y la autorización de sus roles para acceder a ciertos endpoints. Los JWT se utilizan como mecanismo para transportar las credenciales del usuario en cada solicitud al servidor después de la autenticación inicial.

## 2. Explicación de Clases y Componentes de Seguridad

### 2.1. User
**Archivo:** `User.java`

**Descripción:** Esta clase representa a un usuario en el sistema. Es una entidad que se almacena en la base de datos y contiene información relevante como nombre de usuario, contraseña, y roles asignados.

**Anotaciones Importantes:**
- `@Entity`: Marca la clase como una entidad de JPA que se corresponde con una tabla en la base de datos.
- `@Table(name = "users")`: Especifica la tabla en la base de datos que almacena los datos del usuario.
- `@Id`: Indica la clave primaria de la entidad.
- `@ManyToMany(fetch = FetchType.EAGER)`: Define una relación muchos a muchos entre los usuarios y los roles, con carga inmediata de los roles cuando se carga un usuario.

**Propósito:** La clase `User` es fundamental para la autenticación y autorización de la aplicación. Contiene los datos de los usuarios que se validarán contra las credenciales suministradas durante el inicio de sesión.

### 2.2. Role
**Archivo:** `Role.java`

**Descripción:** La clase `Role` representa un rol de usuario en el sistema, como `ADMIN` o `USER`. Estos roles determinan los permisos que tiene un usuario dentro de la aplicación.

**Anotaciones Importantes:**
- `@Entity`: Similar a la clase `User`, `Role` es una entidad JPA.
- `@Table(name = "roles")`: Define la tabla de la base de datos que almacena los roles.
- `@Id`: Marca la clave primaria de la entidad.

**Propósito:** Los roles son esenciales para la autorización. A cada usuario se le asigna uno o más roles que determinan su acceso a diferentes partes de la aplicación.

### 2.3. UserRepository
**Archivo:** `UserRepository.java`

**Descripción:** Esta interfaz extiende `JpaRepository<User, Long>` y proporciona métodos CRUD para manejar la entidad `User`.

**Métodos Clave:**
- `Optional<User> findByUsername(String username)`: Este método se utiliza para encontrar un usuario por su nombre de usuario. Es crucial para la autenticación.

**Propósito:** `UserRepository` es utilizado por los servicios de Spring Security para cargar los detalles de un usuario, específicamente durante la autenticación.

### 2.4. RoleRepository
**Archivo:** `RoleRepository.java`

**Descripción:** Similar a `UserRepository`, `RoleRepository` extiende `JpaRepository<Role, Long>` y proporciona métodos para interactuar con la entidad `Role`.

**Propósito:** Es utilizado para manejar los roles en la base de datos, especialmente durante la asignación de roles a los usuarios.

### 2.5. UserController
**Archivo:** `UserController.java`

**Descripción:** Este controlador gestiona las solicitudes relacionadas con los usuarios.

**EndPoints Importantes:**
- `@PostMapping("/login")`: Maneja la autenticación de usuarios y la generación de JWT.
- `@PostMapping("/register")`: Permite registrar nuevos usuarios en la base de datos.

**Propósito:** `UserController` expone los endpoints públicos para el registro de nuevos usuarios y el inicio de sesión, que son fundamentales para la autenticación y la emisión de JWT.

## 2.6. Seguridad: Configuración y Filtros

### 2.6.1. JwtConfig
**Archivo:** `JwtConfig.java`

**Descripción:** Esta clase contiene la configuración del JWT, como el secreto utilizado para firmar los tokens, la expiración del token, y la cabecera donde se espera encontrar el token.

**Propiedades Importantes:**
- `private String secretKey`: Clave secreta para firmar los JWT.
- `private long validityInMilliseconds`: Duración de la validez del token.

**Propósito:** `JwtConfig` proporciona todos los parámetros necesarios para la creación y validación de JWT en la aplicación.

### 2.6.2. SecurityConfig
**Archivo:** `SecurityConfig.java`

**Descripción:** Configura la seguridad de la aplicación usando Spring Security. Define qué rutas están protegidas y cuáles son públicas, además de establecer la configuración del manejo de JWT.

**Configuraciones Importantes:**
- `@Override protected void configure(HttpSecurity http)`: Configura la seguridad de HTTP, definiendo qué endpoints están protegidos y cuáles no.
- `http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)`: Añade el filtro de autenticación JWT antes del filtro estándar de autenticación de usuario y contraseña.

**Propósito:** `SecurityConfig` es el núcleo de la configuración de seguridad. Controla cómo se manejan las solicitudes, qué usuarios pueden acceder a qué rutas, y cómo se validan los tokens JWT.

### 2.6.3. JwtAuthenticationFilter
**Archivo:** `JwtAuthenticationFilter.java`

**Descripción:** Este filtro maneja la autenticación inicial de los usuarios. Si las credenciales son correctas, genera un JWT y lo envía en la respuesta.

**Métodos Clave:**
- `@Override protected void successfulAuthentication(...)`: Genera el JWT tras una autenticación exitosa y lo incluye en la cabecera de la respuesta.

**Propósito:** Proporciona el mecanismo para crear y enviar el JWT una vez que el usuario se ha autenticado correctamente.

### 2.6.4. JwtValidationFilter
**Archivo:** `JwtValidationFilter.java`

**Descripción:** Este filtro se ejecuta para cada solicitud protegida. Extrae el JWT de la cabecera de la solicitud, lo valida, y si es válido, configura el contexto de seguridad para que Spring Security lo maneje.

**Métodos Clave:**
- `@Override protected void doFilterInternal(...)`: Se encarga de la validación del JWT y de la configuración del contexto de seguridad.

**Propósito:** `JwtValidationFilter` asegura que cada solicitud que llegue a un endpoint protegido esté acompañada de un JWT válido.

## 2.7. JpaUserDetailsService
**Archivo:** `JpaUserDetailsService.java`

**Descripción:** Este servicio implementa `UserDetailsService` de Spring Security, que se utiliza para cargar los detalles del usuario desde la base de datos durante la autenticación.

**Métodos Clave:**
- `@Override public UserDetails loadUserByUsername(String username)`: Carga un usuario por su nombre de usuario y construye un objeto `UserDetails` con sus roles.

**Propósito:** Es el puente entre la base de datos y Spring Security. `JpaUserDetailsService` carga los detalles del usuario que Spring Security necesita para autenticarse y autorizar.

## 3. Funcionamiento del JWT en la Aplicación

### 3.1. Creación de JWT
El JWT se crea durante el proceso de autenticación. Cuando un usuario envía su nombre de usuario y contraseña al endpoint de login, `JwtAuthenticationFilter` valida las credenciales. Si son correctas, el filtro genera un JWT utilizando `JwtConfig` y lo devuelve al usuario en la respuesta. Este token contiene información codificada como el nombre de usuario y roles del usuario, firmado digitalmente con la clave secreta definida en `JwtConfig`.

### 3.2. Uso del JWT para Acceder a Endpoints Protegidos
Para acceder a cualquier endpoint protegido por la seguridad de Spring, el usuario debe enviar el JWT en la cabecera de la solicitud bajo `Authorization`. `JwtValidationFilter` intercepta las solicitudes, extrae el token, y lo valida. Si el token es válido, configura el contexto de seguridad con los detalles del usuario, permitiendo que Spring Security gestione la solicitud como si el usuario estuviera autenticado.

### 3.3. Expiración y Renovación del JWT
El token JWT tiene una duración limitada, configurada en `JwtConfig`. Si un token ha expirado, el usuario debe autenticarse nuevamente para obtener uno nuevo. Esta estrategia protege contra el uso no autorizado de tokens antiguos.

## 4. Conclusión
El sistema de seguridad basado en JWT implementado en esta aplicación es un enfoque robusto para autenticar y autorizar a los usuarios. Utiliza Spring Security junto con JWT para asegurar que sólo los usuarios autenticados y autorizados puedan acceder a recursos sensibles. Las configuraciones y clases discutidas trabajan en conjunto para proporcionar una capa de seguridad que protege la aplicación contra accesos no autorizados, asegurando que todas las solicitudes sean verificadas antes de ser procesadas.
