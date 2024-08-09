package com.app.springboot.springboot_crud.entities;

import java.util.*;

import com.app.springboot.springboot_crud.validation.ExistsByUsername;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    @ExistsByUsername
    @NotBlank
    @Size(min = 4, max = 12)
    private String username;

    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    /*
     * Se usa JsonIgnoreProperties, ya que la clase User Y Role estan en una
     * relación ManyToMany bidireccional, y al llamar al métod GET que lista los
     * objetos, se ciclan en un bucle infinito
     * 
     * En Spring Boot, cuando trabajas con relaciones bidireccionales Many-To-Many
     * en entidades JPA, es común enfrentar problemas de serialización que pueden
     * llevar a bucles infinitos. Esto sucede porque cada lado de la relación
     * contiene una referencia al otro, y al intentar serializar un objeto, se
     * intenta serializar también su relación, lo que a su vez intenta serializar la
     * relación del otro lado, y así sucesivamente.
     * 
     * Para evitar esto, puedes usar la anotación @JsonIgnoreProperties para ignorar
     * ciertas propiedades durante la serialización.
     * 
     * users: Esta es la propiedad de la relación bidireccional que causa el bucle
     * infinito. Al ignorar esta propiedad en una de las entidades, evitamos que la
     * serialización de un objeto cause la serialización recursiva de la colección
     * de objetos relacionados.
     * Este uso es esencial para romper el ciclo de serialización. Por ejemplo, si
     * tienes una entidad Group con una lista de User y una entidad User con una
     * lista de Group, ignorar la propiedad users en Group evitará que al serializar
     * un User se intente serializar la lista de Group completa, la cual a su vez
     * intentaría serializar la lista de User completa, y así sucesivamente.
     * 
     * handler: Esta propiedad es un objeto proxy que Hibernate utiliza internamente
     * para manejar la carga perezosa (lazy loading) de entidades. No es relevante
     * para la lógica de la aplicación y, de hecho, su serialización puede causar
     * problemas.
     * Ignorar esta propiedad evita errores relacionados con la serialización de
     * objetos proxy que Hibernate utiliza para implementar la carga diferida. La
     * propiedad handler no debería estar en el JSON de salida ya que es específica
     * de la implementación de Hibernate y no aporta valor al consumidor del API.
     * 
     * hibernateLazyInitializer: Similar al handler, esta propiedad es utilizada
     * internamente por Hibernate para gestionar la carga perezosa. No tiene sentido
     * incluirla en la salida JSON porque es un detalle de implementación interna
     * que no debería ser expuesto.
     * Ignorar esta propiedad evita la serialización de un proxy que Hibernate
     * utiliza internamente. De nuevo, estos son detalles de implementación que no
     * son relevantes para la representación JSON de la entidad.
     * 
     */

    @JsonIgnoreProperties({ "users", "handler", "hibernateLazyInitializer" })
    @ManyToMany
    @JoinTable(name = "users_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"), uniqueConstraints = {
            @UniqueConstraint(columnNames = { "user_id", "rol_id" }) })
    private List<Role> roles;

    private boolean enabled;

    @PrePersist
    public void prePersist() {
        this.enabled = true;
    }

    /*
     * Transient se usa para indicar a JPA e Hibernate que el atributo admin no está
     * mapeado a ningun campo en la tabla
     */
    @Transient
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private boolean admin;

    public User() {
        this.roles = new ArrayList<>();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public boolean isAdmin() {
        return admin;
    }

    public void setAdmin(boolean admin) {
        this.admin = admin;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof User)) {
            return false;
        }
        User user = (User) o;
        return Objects.equals(id, user.id) && Objects.equals(username, user.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username);
    }

}
