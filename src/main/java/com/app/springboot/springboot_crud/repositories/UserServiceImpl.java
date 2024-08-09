package com.app.springboot.springboot_crud.repositories;

import java.util.List;
import java.util.Optional;
import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.springboot.springboot_crud.entities.Role;
import com.app.springboot.springboot_crud.entities.User;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    @Override
    public List<User> findAll() {
        List<User> users = (List<User>) repository.findAll();
        users.forEach(user -> {
            boolean isAdmin = user.getRoles().stream().anyMatch(rol -> rol.getName().equals("ROLE_ADMIN"));
            user.setAdmin(isAdmin);
        });
        return users;
    }

    @Transactional
    @Override
    public User save(User user) {

        Optional<Role> optionalRoleUser = roleRepository.findByName("ROLE_USER");
        List<Role> roles = new ArrayList<>();

        optionalRoleUser.ifPresent(roles::add);

        // if (user.isAdmin()) {
        // Optional<Role> optionalRoleAdmin = roleRepository.findByName("ROLE_ADMIN");
        // optionalRoleAdmin.ifPresent(roles::add);
        // user.setAdmin(true);
        // }

        user.setRoles(roles);

        String passwordEncoded = passwordEncoder.encode(user.getPassword());
        user.setPassword(passwordEncoded);

        return repository.save(user);
    }

    @Override
    public boolean existsByUsername(String username) {
        return repository.existsByUsername(username);
    }

}
