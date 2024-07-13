package com.example.shiro_jwt.core.shiro;

import com.example.shiro_jwt.core.shiro.utils.JwtUtil;
import com.example.shiro_jwt.model.User;
import com.example.shiro_jwt.service.IUserService;
import org.apache.catalina.security.SecurityUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * @author moli
 * @time 2024-07-13 15:35:15
 * @description 用户名密码登录
 */
public class UsernamePasswordTokenRealm extends AuthorizingRealm {

    private final IUserService userService;

    private final RedisTemplate redisTemplate;

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    public UsernamePasswordTokenRealm(IUserService userService, RedisTemplate redisTemplate) {
        this.userService = userService;
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected boolean hasRole(String roleIdentifier, AuthorizationInfo info) {
        if (Objects.isNull(info)) return false;
        if (info.getRoles().contains("admin")) {
            return true;
        }
        return info.getRoles().contains(roleIdentifier);
    }

    /**
     * 授权
     * @param principals the primary identifying principals of the AuthorizationInfo that should be retrieved.
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = principals.toString();
        SimpleAuthorizationInfo auth = new SimpleAuthorizationInfo();
        Map<String, Set<String>> map = this.userService.getRolesAndPermissionsByUserName(username);
        auth.setRoles(map.get("roles"));
        auth.setStringPermissions(map.get("perms"));
        return auth;
    }

    /**
     * 认证
     * @param token the authentication token containing the user's principal and credentials.
     * @return AuthenticationInfo
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        String username = usernamePasswordToken.getUsername();

        // 根据用户名查询用户
        User storegeUser = userService.getUserByUserName(username);
        if (Objects.isNull(storegeUser)) {
            throw new UnknownAccountException("该帐号不存在！");
        }
        ByteSource salt = null;

        // 设置盐值
        String saltStr = storegeUser.getSalt();
        if (StringUtils.hasLength(saltStr)) {
            salt = ByteSource.Util.bytes(saltStr);
        }

        return new SimpleAuthenticationInfo(username, storegeUser.getPassword(), salt, storegeUser.getRealName());
    }
}
