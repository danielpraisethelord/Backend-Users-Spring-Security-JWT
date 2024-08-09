package com.app.springboot.springboot_crud.validation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.app.springboot.springboot_crud.services.ProductService;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

@Component
public class IsExistsValidation implements ConstraintValidator<IsExistsDB, String> {

    @Autowired
    private ProductService service;

    @Override
    public boolean isValid(String arg0, ConstraintValidatorContext arg1) {
        if (service == null)
            return true;

        return !service.existsBySku(arg0);
    }

}
