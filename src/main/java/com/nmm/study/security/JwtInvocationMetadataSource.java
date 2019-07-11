package com.nmm.study.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;

@Component
public class JwtInvocationMetadataSource extends DefaultFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private AntPathMatcher matcher = new AntPathMatcher();

    public JwtInvocationMetadataSource() {
        super(new LinkedHashMap<>());
    }

    /**
     * 根据请求获取权限要求filterInvocation
     * @param object
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation filterInvocation = (FilterInvocation) object;
        System.out.println("获取权限规则：" + filterInvocation.getRequestUrl());
        filterInvocation.getRequestUrl();
        for (ConfigAttribute configAttribute : getAllConfigAttributes()) {
            JwtConfigAttribute attribute = (JwtConfigAttribute) configAttribute;
            if (matcher.match(attribute.getPath(),filterInvocation.getRequestUrl())){
                return Arrays.asList(attribute);
            }
        }
        return null;
    }

    /**
     * 获取所有角色
     * @return
     */
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        JwtConfigAttribute configAttribute = new JwtConfigAttribute();
        configAttribute.setPath("/api/book");
        configAttribute.setRoles(Arrays.asList("admin".toUpperCase()));
        return Arrays.asList(configAttribute);
    }

}
