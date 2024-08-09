package com.app.springboot.springboot_crud.repositories;

import java.util.*;

import org.springframework.data.repository.CrudRepository;

import com.app.springboot.springboot_crud.entities.Role;

public interface RoleRepository extends CrudRepository<Role, Long> {

    Optional<Role> findByName(String name);
}
