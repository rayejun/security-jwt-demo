package io.github.rayejun.securityjwt.controller;

import io.github.rayejun.securityjwt.config.security.AnonymousAccess;
import io.github.rayejun.securityjwt.utils.Constants;
import io.github.rayejun.securityjwt.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.List;

@RestController
public class UserController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @AnonymousAccess
    @RequestMapping("login")
    @SuppressWarnings("unchecked")
    public Object login(String username, String password, HttpServletResponse response) {
        // 通过用户名和密码创建一个 Authentication 认证对象，实现类为 UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        try {
            //通过 AuthenticationManager（默认实现为ProviderManager）的authenticate方法验证 Authentication 对象
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            //将 Authentication 绑定到 SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            UserDetails userDetails = (UserDetails) principal;
            //生成Token
            String token = JwtTokenUtil.createToken(userDetails.getUsername(), "1", (List<SimpleGrantedAuthority>) userDetails.getAuthorities());
            //将Token写入到Http头部
            response.addHeader(Constants.AUTHORIZATION_HEADER, Constants.AUTHORIZATION_PREFIX + token);
            return "success token：" + token;
        } catch (UsernameNotFoundException e) {
            return "登录名不正确";
        } catch (BadCredentialsException e) {
            return "密码不正确";
        }
    }

    @AnonymousAccess
    @RequestMapping("index")
    public Object index() {
        return "index";
    }

    @RequestMapping("home")
    public Object home() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ((UserDetails) principal).getUsername();
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @RequestMapping("user")
    public String user() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ((UserDetails) principal).getUsername();
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @RequestMapping("admin")
    public String admin() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ((UserDetails) principal).getUsername();
    }
}
