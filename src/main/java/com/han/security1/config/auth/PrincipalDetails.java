package com.han.security1.config.auth;

import com.han.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인 진행.
// 로그인 진행이 완료가되면 시큐리티 session을 만들어준다.(Security ContextHolder)
// Security Session => Authentication => UserDetails(PrincipalDetails)
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; //콤포지션 (객체)
    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user){
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes){
        this.user = user;
        this.attributes = attributes;
    }

    // User의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정이 만료가 안되었는가?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}
