package io.github.rayejun.securityjwt.config.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    private static final String ID_FOR_PASSWORD_ENCODE = "{bcrypt}";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        throw new UsernameNotFoundException(username + " not found");
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new User(username, ID_FOR_PASSWORD_ENCODE + "$2a$10$OcJqb2haehNP.tb7upQIAerDXBfWzbfontsuskYJavpDyh5jA0qW.", authorities);
    }
}
