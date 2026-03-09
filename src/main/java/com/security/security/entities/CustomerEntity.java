package com.security.security.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.io.Serializable;

@Entity
@Table(name = "customers")
@Data
public class CustomerEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    private Long id;
    private String email;
    @Column(name = "pwd")
    private String password;
    @Column(name = "rol")
    private String rol;
}
