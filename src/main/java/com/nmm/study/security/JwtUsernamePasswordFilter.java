package com.nmm.study.security;

import com.nmm.study.util.JwtUtil;
import lombok.Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.StringJoiner;

/**
 * 我们要重写登录认证，用于实现登录确认。
 */
@Data
public class JwtUsernamePasswordFilter extends UsernamePasswordAuthenticationFilter {

    private JwtUtil jwtUtil;

    /**
     * 登录成功
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        UserDetails details = (UserDetails) authResult.getPrincipal();
        System.out.println("登录成功：" + details.getUsername());

        StringJoiner joiner = new StringJoiner(",","","");
        details.getAuthorities().forEach(a -> joiner.add(a.getAuthority()));

        String token = jwtUtil.createToken("username",details.getUsername(),"role",joiner.toString());
        response.setHeader("Authorization",token);

    }

    /**
     * 登录失败
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }
}
