package com.app.springboot.springboot_crud.repositories;

import org.springframework.data.repository.CrudRepository;

import com.app.springboot.springboot_crud.entities.User;
import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {
    boolean existsByUsername(String username);

    Optional<User> findByUsername(String username);
}
