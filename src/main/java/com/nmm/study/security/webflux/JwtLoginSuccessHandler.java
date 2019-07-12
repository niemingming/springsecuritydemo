package com.nmm.study.security.webflux;

import com.nmm.study.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.StringJoiner;

@Component
public class JwtLoginSuccessHandler implements ServerAuthenticationSuccessHandler {
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {

        UserDetails details = (UserDetails) authentication.getPrincipal();
        System.out.println("登录成功：" + details.getUsername());

        StringJoiner joiner = new StringJoiner(",","","");
        details.getAuthorities().forEach(a -> joiner.add(a.getAuthority()));

        String token = jwtUtil.createToken("username",details.getUsername(),"role",joiner.toString());
//        webFilterExchange..setHeader("Authorization",token);
        webFilterExchange.getExchange().getResponse().getHeaders().add("Authorization",token);
        return webFilterExchange.getExchange().getResponse().setComplete();
    }
}
