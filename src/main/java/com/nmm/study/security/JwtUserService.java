package com.nmm.study.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Arrays;

/**
 * 自定义人员信息加载接口
 */
@Component
public class JwtUserService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("加载人员信息数据，包括角色信息！");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //我们暂时不实现UserDetails，使用默认的User，后面考虑查询数据库
        if (authentication != null) {
            return new User(authentication.getName(),null,authentication.getAuthorities());
        }else {
            return new User(username,passwordEncoder.encode("123456"), Arrays.asList(new SimpleGrantedAuthority("ADMIN")));
        }
    }
}
