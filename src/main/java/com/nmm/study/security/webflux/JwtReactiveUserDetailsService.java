package com.nmm.study.security.webflux;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * 用于获取用户基本信息的数据
 */
@Component
public class JwtReactiveUserDetailsService implements ReactiveUserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 模拟操作
     * @param username
     * @return
     */
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        System.out.println("获取用户信息：" + username);
        //指定密码编译器
        return Mono.just(User.withUsername(username).passwordEncoder(passwordEncoder::encode)
                              .password("123456")
                                .authorities("admin".toUpperCase())
                                .build());
    }
}
