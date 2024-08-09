package com.app.springboot.springboot_crud.repositories;

import org.springframework.data.repository.CrudRepository;

import com.app.springboot.springboot_crud.entities.Product;

public interface ProductRepository extends CrudRepository<Product, Long> {
    boolean existsBySku(String sku);
}
