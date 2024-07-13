package com.example.shiro_jwt.core.shiro.filter;

import com.example.shiro_jwt.core.shiro.JwtToken.JwtToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class JwtFilter extends BasicHttpAuthenticationFilter {

    @Value("${jwt.anonymous.urls}")
    private String anonymousStr;

    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        String contextPath = WebUtils.getPathWithinApplication(WebUtils.toHttp(servletRequest));
        // 白名单
        if (!StringUtils.isEmpty(anonymousStr)) {
            String[] anonUrls = anonymousStr.split(",");
            for (int i = 0; i < anonUrls.length; i++) {
                if (contextPath.contains(anonUrls[i])) {
                    return true;
                }
            }
        }

        // 判断是否是通过 rememberMe 已经登录了
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated() && subject.isRemembered()) {
            return true;
        }

        //获取请求头 token 并登录
        AuthenticationToken token = this.createToken(servletRequest, servletResponse);
        subject.login(token);
        return true;
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest servletRequest, ServletResponse servletResponse) {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String token = request.getHeader("Authorization");
        return new JwtToken(token);
    }
}
