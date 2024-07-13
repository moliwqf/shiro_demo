package com.example.shiro_jwt.core.shiro.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private static String tokenExpireTime; // token 过期时间

    public static final String TOKEN_SECRET = "APP";

    @Value("${jwt.tokenExpireTime}")
    public void setTokenExpireTime(String tokenExpireTime) {
        JwtUtil.tokenExpireTime = tokenExpireTime;
    }

    /**
     * 获得 token 中的信息无需 secret 解密也能获得
     *
     * @return token 中包含的用户名
     */
    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 检验token是否正确
     * @param token 需要校验的token
     * @return 校验是否成功
     */
    public static boolean verify(String token){
        try {
            //设置签名的加密算法：HMAC256
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (Exception e){
            return false;
        }
    }


    /**
     * 生成签名,30min后过期
     *
     * @param username 用户名
     * @return 加密的token
     */
    public static String sign(String username) {
        try {
            // token 过期时间
            Date date = new Date(System.currentTimeMillis() + (Long.parseLong(tokenExpireTime) * 60 * 1000));
            // 附带 username 信息
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            return JWT.create()
                    .withClaim("username", username)
                    .withExpiresAt(date)
                    .sign(algorithm);
        } catch (Exception e) {
            return null;
        }
    }
}