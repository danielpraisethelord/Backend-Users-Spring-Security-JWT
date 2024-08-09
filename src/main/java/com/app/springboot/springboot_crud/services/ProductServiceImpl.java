package com.app.springboot.springboot_crud.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.springboot.springboot_crud.entities.Product;
import com.app.springboot.springboot_crud.repositories.ProductRepository;

@Service
public class ProductServiceImpl implements ProductService {

    @Autowired
    private ProductRepository repository;

    @Transactional(readOnly = true)
    @Override
    public List<Product> findAll() {
        return (List<Product>) repository.findAll();
    }

    @Transactional(readOnly = true)
    @Override
    public Optional<Product> findById(Long id) {
        return repository.findById(id);
    }

    @Transactional
    @Override
    public Product save(Product product) {
        return repository.save(product);
    }

    @Transactional
    @Modifying
    @Override
    public Optional<Product> update(Long id, Product product) {
        Optional<Product> productOptionalDB = repository.findById(id);
        if (productOptionalDB.isPresent()) {
            Product productDB = productOptionalDB.orElseThrow();

            productDB.setSku(product.getSku());
            productDB.setName(product.getName());
            productDB.setDescription(productDB.getDescription());
            productDB.setPrice(product.getPrice());
            return Optional.of(repository.save(productDB));
        }
        return productOptionalDB;
    }

    @Transactional
    @Modifying
    @Override
    public Optional<Product> delete(Long id) {
        Optional<Product> productOptionalDB = repository.findById(id);
        productOptionalDB.ifPresent(repository::delete);
        return productOptionalDB;
    }

    @Transactional(readOnly = true)
    @Override
    public boolean existsBySku(String sku) {
        return repository.existsBySku(sku);
    }

}
