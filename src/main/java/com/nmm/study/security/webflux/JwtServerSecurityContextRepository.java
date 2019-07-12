package com.nmm.study.security.webflux;

import com.nmm.study.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 登陆后权限处理
 */
@Component
public class JwtServerSecurityContextRepository implements ServerSecurityContextRepository {
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * 不保存
     * @param exchange
     * @param context
     * @return
     */
    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();
    }

    /**
     * 加载信息,这里同时承载了用户信息
     * @param exchange
     * @return
     */
    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        System.out.println("进来了，校验登录信息！");
        SecurityContext context = null;

        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (auth == null) {
            return Mono.empty();
        }
        String username = jwtUtil.parseToken(auth).get("username")+"";
        String role = jwtUtil.parseToken(auth).get("role")+"";
        //读取权限
        List<GrantedAuthority> grantedAuthorities = Arrays.asList(role.split(",")).stream()
                .map(r -> {
                    return new SimpleGrantedAuthority(r);
                }).collect(Collectors.toList());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
        context = new SecurityContextImpl(token);
        return Mono.justOrEmpty(context);
    }
}
