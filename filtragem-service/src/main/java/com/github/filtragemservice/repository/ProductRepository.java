package com.github.filtragemservice.repository;

import com.github.filtragemservice.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ProductRepository extends JpaRepository<Product, Integer> {

    @Query("Select p from Product p where p.owner=?#{authentication.name}")
    List<Product> findProductByDescribeContains();
}
