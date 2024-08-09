package com.app.springboot.springboot_crud.repositories;

import java.util.*;

import com.app.springboot.springboot_crud.entities.User;

public interface UserService {

    List<User> findAll();

    User save(User user);

    boolean existsByUsername(String username);
}
