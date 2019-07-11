package com.nmm.study.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil implements InitializingBean{
    @Value("${jwt.security.key}")
    private String keystr;

    private Key key;

    /**
     * 生成jwt文件
     * @param data
     * @return
     */
    public String createToken(String ... data) {
        if (data.length%2 == 1){
            throw new RuntimeException("数据存在问题！");
        }
        Map<String,Object> map = new HashMap<>();
        for (int i = 0; i < data.length; i++) {
            map.put(data[i++],data[i]);
        }
        //暂时不考虑过期时间
        return Jwts.builder().signWith(key).setClaims(map).compact();
    }

    /**
     * 解密token
     * @param str
     * @return
     */
    public Map parseToken(String str){
        Claims claims = (Claims) Jwts.parser().setSigningKey(key).parse(str).getBody();
        return claims;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        key = Keys.hmacShaKeyFor(Hex.decode(keystr));
    }
}
