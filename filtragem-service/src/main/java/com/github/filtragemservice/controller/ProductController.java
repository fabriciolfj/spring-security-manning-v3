package com.github.filtragemservice.controller;

import com.github.filtragemservice.entity.Product;
import com.github.filtragemservice.repository.ProductRepository;
import com.github.filtragemservice.service.ProductService;
import org.aspectj.weaver.ast.Literal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class ProductController {

    @Autowired
    private ProductService productService;
    @Autowired
    private ProductRepository productRepository;

    @GetMapping("/products")
    public List<Product> findProductsContaining() {
        return productRepository.findProductByDescribeContains();
    }

    @GetMapping("/sell")
    public List<Product> sell() {
        var products = new ArrayList<Product>();

        products.add(new Product(1, "fabricio", "arroz"));
        products.add(new Product(2, "fabricio", "feijao"));
        products.add(new Product(3, "suzy", "farinha"));

        return productService.execute(products);
    }

    @GetMapping("/find")
    public List<Product> findProducts() {
        return productService.findProducts();
    }
}
