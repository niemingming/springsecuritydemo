package com.nmm.study.security.webflux;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 自定义校验规则，我们需要的话，其他只需要一个指定需要检验即可
 */
@Component
public class JwtReactiveAuthorizationManager implements ReactiveAuthorizationManager<ServerWebExchange>,InitializingBean{

    private Map<String,List<String>> grantes = new HashMap<>();
    private AntPathMatcher matcher = new AntPathMatcher();

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, ServerWebExchange exchange) {
        System.out.println("check granted::" + exchange.getRequest().getURI().getPath());

        return Flux.fromIterable(grantes.entrySet())
                .filter(grant -> matcher.match(grant.getKey(),exchange.getRequest().getURI().getPath()))
                .flatMap(g -> authentication.flatMap(au ->{
                    long count = au.getAuthorities().stream().filter( grantedAuthority -> {
                        return g.getValue().contains(grantedAuthority.getAuthority().toLowerCase());
                    }).count();
                    return Mono.just(new AuthorizationDecision(count > 0));
                })).next().defaultIfEmpty(new AuthorizationDecision(false));

    }

    @Override
    public void afterPropertiesSet() throws Exception {
        grantes.clear();
        grantes.put("/api/book", Arrays.asList("admin","employee"));

    }

}
