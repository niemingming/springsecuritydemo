package com.nmm.study.security;

import com.nmm.study.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtUserService jwtUserService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private JwtInvocationMetadataSource jwtInvocationMetadataSource;
    @Autowired
    private JwtAutheticationVotor jwtAutheticationVotor;
    /**
     * 配置鉴权信息
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserService)
                .passwordEncoder(passwordEncoder());//指定密码处理器
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    /**
     * 配置鉴权信息
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .accessDecisionManager(accessDecisionManager())//权限验证处理
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {//权限规则获取
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setSecurityMetadataSource(jwtInvocationMetadataSource);
                        return object;
                    }
                })
                .antMatchers("/api/book").hasAnyRole("admin".toUpperCase())
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
//                .sessionManagement().disable()
                .addFilterBefore(usernamePasswordAuthenticationFilter(), LogoutFilter.class)
                .addFilterBefore(jwtInfoFilter(),LogoutFilter.class);
    }

    @Bean
    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        JwtUsernamePasswordFilter usernamePasswordFilter = new JwtUsernamePasswordFilter();
        usernamePasswordFilter.setAuthenticationManager(authenticationManagerBean());
        usernamePasswordFilter.setJwtUtil(jwtUtil);
        return usernamePasswordFilter;
    }
    @Bean
    public JwtInfoFilter jwtInfoFilter() throws Exception {
        JwtInfoFilter filter = new JwtInfoFilter(authenticationManagerBean());
        filter.setJwtUtil(jwtUtil);
        return filter;
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDecisionManager accessDecisionManager(){

        List<AccessDecisionVoter<? extends Object>> voters = new ArrayList<>();
        voters.add(new WebExpressionVoter());
        voters.add(new JwtAutheticationVotor());

        AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
        return accessDecisionManager;
    }
}
