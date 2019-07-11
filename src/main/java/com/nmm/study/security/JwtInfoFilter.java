package com.nmm.study.security;

import com.nmm.study.util.JwtUtil;
import lombok.Data;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 读取请求头并处理,设置登录信息
 */
@Data
public class JwtInfoFilter extends BasicAuthenticationFilter {

    private JwtUtil jwtUtil;

    public JwtInfoFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String auth = request.getHeader("Authorization");
        if (auth == null) {
            chain.doFilter(request,response);
            return;
        }
        String username = jwtUtil.parseToken(auth).get("username")+"";
        String role = jwtUtil.parseToken(auth).get("role")+"";
        //读取权限
        List<GrantedAuthority> grantedAuthorities = Arrays.asList(role.split(",")).stream()
                .map(r -> {
                    return new SimpleGrantedAuthority(r);
                }).collect(Collectors.toList());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(token);

        chain.doFilter(request,response);
    }
}
