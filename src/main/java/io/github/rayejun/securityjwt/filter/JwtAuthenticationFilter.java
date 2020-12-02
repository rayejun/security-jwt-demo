package io.github.rayejun.securityjwt.filter;

import io.github.rayejun.securityjwt.utils.Constants;
import io.github.rayejun.securityjwt.utils.JwtTokenUtil;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = resolveToken(request);

        if (StringUtils.hasText(token)) {
            try {
                JwtTokenUtil.validateToken(token);
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    Authentication authentication = getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
                chain.doFilter(request, response);
            } catch (RuntimeException e) {
                response.setContentType("application/json; charset=utf-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(e.getMessage());
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(Constants.AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(Constants.AUTHORIZATION_PREFIX)) {
            return bearerToken.substring(7);
        }
        String token = request.getParameter(Constants.AUTHORIZATION_PARAMETER);
        if (StringUtils.hasText(token)) {
            return token;
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String username = claims.getSubject();
            List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(claims.getStringClaim(Constants.AUTHORITIES_KEY));

            User principal = new User(username, "", authorities);
            return new UsernamePasswordAuthenticationToken(principal, "", authorities);
        } catch (ParseException e) {
            logger.error("getAuthentication", e);
        }
        return null;
    }
}
