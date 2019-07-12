package com.nmm.study.security.webflux;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;

/**
 * 基于webflux模式的security配置
 * 代码餐卡EnableWebFluxSecurity的注释
 *
 * AuthenticationWebFilter:登录
 * AuthorizationWebFilter: 鉴权
 * ReactorContextWebFilter:过滤获取权限信息通过ServerSecurityContextRepository获取权限信息
 *
 * 从注解进入相关引入的配置，我们可以看到webflux的配置，更多的使用了spring的特性。
 * 我们注入了bean，就会使用。
 *
 * 关键过滤器是webfilter
 *
 */
@EnableWebFluxSecurity
public class JwtWebFluxSecurityConfiguration {
    @Autowired
    private JwtLoginSuccessHandler jwtLoginSuccessHandler;
    @Autowired
    private JwtServerSecurityContextRepository jwtServerSecurityContextRepository;
    @Autowired
    private JwtReactiveAuthorizationManager jwtReactiveAuthorizationManager;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity){

        httpSecurity.authorizeExchange()
                .anyExchange().authenticated()
                .and()
                .addFilterAt(new AuthorizationWebFilter(jwtReactiveAuthorizationManager), SecurityWebFiltersOrder.AUTHORIZATION)
                .csrf().disable()//暂时禁用，不考虑csrf攻击我们不适用session
                .securityContextRepository(jwtServerSecurityContextRepository)
                .formLogin()
                .authenticationSuccessHandler(jwtLoginSuccessHandler);
        //从源码看，其formlogin是写死的参数获取方式，我们如果要覆盖不通过form表单获取登录信息。

        return httpSecurity.build();
    }
}
