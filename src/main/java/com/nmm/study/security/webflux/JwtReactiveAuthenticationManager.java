package com.nmm.study.security.webflux;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.cache.CacheFlux;
import reactor.cache.CacheMono;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager,InitializingBean{
    //默认的权限配置要求，我们可以改成数据库的或者其他形式
    private Map<String,List<String>> grantes = new HashMap<>();


    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return null;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }
}
