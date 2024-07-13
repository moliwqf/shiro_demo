package com.example.shiro_jwt.core.shiro;

import com.alibaba.fastjson.JSON;
import com.example.shiro_jwt.core.shiro.JwtToken.JwtToken;
import com.example.shiro_jwt.core.shiro.utils.JwtUtil;
import com.example.shiro_jwt.model.User;
import com.example.shiro_jwt.service.IUserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class JwtTokenRealm extends AuthorizingRealm {

    @Autowired
    private IUserService userService;

    @Autowired
    private RedisTemplate redisTemplate;

    public static final String USER_INFO_REDIS_PREFIX = "user:";

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected boolean hasRole(String roleIdentifier, AuthorizationInfo info) {
        if (Objects.isNull(info)) return false;
        if (info.getRoles().contains("admin")) {
            return true;
        }
        return info.getRoles().contains(roleIdentifier);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = JwtUtil.getUsername(principals.toString());
        if (StringUtils.isEmpty(username)) {
            return null;
        }
        SimpleAuthorizationInfo auth = new SimpleAuthorizationInfo();
        Map<String, Set<String>> map = this.userService.getRolesAndPermissionsByUserName(username);
        auth.setRoles(map.get("roles"));
        auth.setStringPermissions(map.get("perms"));
        return auth;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        JwtToken jwtToken = (JwtToken) token;

        // 获取 token 并验证
        String tokenStr = jwtToken.getToken();
        if (!JwtUtil.verify(tokenStr)) {
            throw new AuthenticationException("token 过期");
        }

        // 从 redis 中获取用户信息
        String username = JwtUtil.getUsername(tokenStr);
        String userStr = (String) redisTemplate.opsForValue().get(USER_INFO_REDIS_PREFIX + username);
        if (StringUtils.isEmpty(userStr)) {
            throw new AuthenticationException("非法 token");
        }

        // 解析 user json
        User storegeUser = JSON.parseObject(userStr, User.class);
        if (Objects.isNull(storegeUser)) {
            throw new AuthenticationException("非法 token");
        }

        ByteSource salt = null;
        String saltStr = storegeUser.getSalt();
        if (StringUtils.hasLength(saltStr)) {
            salt = ByteSource.Util.bytes(saltStr);
        }
        return new SimpleAuthenticationInfo(username, storegeUser.getPassword(), salt, storegeUser.getRealName());
    }
}
