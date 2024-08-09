package com.app.springboot.springboot_crud.services;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.springboot.springboot_crud.entities.User;
import com.app.springboot.springboot_crud.repositories.UserRepository;

/**
 * En Spring Boot 3, la interfaz UserDetailsService es parte del módulo de
 * seguridad de Spring (Spring Security) y se utiliza para la autenticación de
 * usuarios. Esta interfaz proporciona un mecanismo estándar para cargar datos
 * específicos del usuario desde una fuente de datos, como una base de datos, a
 * partir del nombre de usuario.
 * 
 * Propósito de UserDetailsService
 * El propósito principal de UserDetailsService es definir un contrato para
 * cargar los detalles del usuario necesario para la autenticación. La interfaz
 * tiene un solo método
 * 
 * Métodos y Funcionalidad
 * loadUserByUsername(String username):
 * Este método toma un nombre de usuario como parámetro y devuelve una instancia
 * de UserDetails.
 * UserDetails es una interfaz que proporciona la información necesaria sobre el
 * usuario para la autenticación, como el nombre de usuario, la contraseña, y
 * los roles o autoridades.
 * Si el usuario no se encuentra, este método debe lanzar una excepción
 * UsernameNotFoundException.
 * 
 * UserDetailsService es una interfaz clave en Spring Security que permite
 * cargar los detalles de un usuario para la autenticación desde una fuente de
 * datos personalizada. Implementarla correctamente es crucial para gestionar la
 * autenticación en aplicaciones Spring Boot.
 */
@Service
// @EnableWebSecurity
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = repository.findByUsername(username);

        if (!userOptional.isPresent()) {
            throw new UsernameNotFoundException(String.format("Username '%s' no existe en el sistema", username));
        }

        User user = userOptional.orElseThrow();

        /*
         * authorities:
         * 
         * Se crea una lista de GrantedAuthority a partir de los roles del usuario. Cada
         * rol se convierte en un SimpleGrantedAuthority que Spring Security puede
         * utilizar para la autorización.
         * 
         * La interfaz GrantedAuthority es parte de Spring Security y representa una
         * autoridad otorgada a un Authentication (generalmente un usuario). En términos
         * sencillos, una autoridad es un privilegio que tiene un usuario, como un rol o
         * un permiso.
         * 
         * Propósito
         * El propósito principal de GrantedAuthority es encapsular y representar los
         * permisos (o roles) asignados a un usuario. Estos permisos se utilizan para
         * tomar decisiones de autorización dentro del sistema de seguridad de Spring.
         */
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        /*
         * Esta línea está creando una nueva instancia de la clase
         * org.springframework.security.core.userdetails.User, que es una implementación
         * estándar de la interfaz UserDetails proporcionada por Spring Security. La
         * clase UserDetails es utilizada por Spring Security para almacenar la
         * información del usuario necesaria para la autenticación y la autorización.
         * 
         * user.getUsername():
         * Este es el nombre de usuario que se utiliza para la autenticación.
         * Se obtiene de la entidad User de tu sistema.
         * 
         * user.getPassword():
         * Este es el hash de la contraseña del usuario que se almacena en la base de
         * datos.
         * Se utiliza para la autenticación al comparar con la contraseña proporcionada
         * por el usuario al iniciar sesión.
         * 
         * user.isEnabled():
         * Este valor indica si la cuenta del usuario está habilitada o no.
         * Si es false, el usuario no podrá autenticarse.
         * 
         * true (primer valor booleano):
         * Este valor indica si la cuenta del usuario no ha expirado.
         * En este caso, se está configurando a true, lo que significa que la cuenta
         * nunca expira.
         * 
         * true (segundo valor booleano):
         * Este valor indica si las credenciales del usuario (por ejemplo, la
         * contraseña) no han expirado.
         * Se configura a true, lo que significa que las credenciales nunca expiran.
         * 
         * true (tercer valor booleano):
         * Este valor indica si la cuenta del usuario no está bloqueada.
         * Se configura a true, lo que significa que la cuenta nunca está bloqueada.
         * 
         * authorities:
         * Este es un List de objetos GrantedAuthority, que representa los roles y
         * permisos otorgados al usuario.
         * En tu ejemplo, esta lista se construye a partir de los roles del usuario,
         * mapeando cada rol a una instancia de SimpleGrantedAuthority.
         */
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                user.isEnabled(), true, true, true, authorities);
    }
}
