package com.nmm.study.security;

import lombok.Data;
import org.springframework.security.access.ConfigAttribute;

import java.util.List;

@Data
public class JwtConfigAttribute implements ConfigAttribute {

    private String path;
    private List<String> roles;
    private String role;

    @Override
    public String getAttribute() {
        return role;
    }
}
