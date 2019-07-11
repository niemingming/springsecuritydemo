package com.nmm.study.security;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class JwtAutheticationVotor implements AccessDecisionVoter<FilterInvocation> {
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof JwtConfigAttribute;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    /**
     * 校验逻辑
     * @param authentication
     * @param object
     * @param attributes
     * @return
     */
    @Override
    public int vote(Authentication authentication, FilterInvocation object, Collection<ConfigAttribute> attributes) {
        if (attributes == null) {
            //无限制
            return ACCESS_GRANTED;
        }
        System.out.println("校验权限：");
        for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
            for (ConfigAttribute attribute : attributes) {
                if (attribute instanceof JwtConfigAttribute){
                    JwtConfigAttribute jwtConfigAttribute = (JwtConfigAttribute) attribute;
                    for (String s : jwtConfigAttribute.getRoles()) {
                        if (s.equalsIgnoreCase(grantedAuthority.getAuthority())){
                            return ACCESS_GRANTED;
                        }
                    }
                }
            }
        }
        return ACCESS_DENIED;
    }
}
