package com.security.security.security;

import org.jspecify.annotations.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//@Component
public class MyPasswordEncoder /*implements PasswordEncoder*/ {

    //@Override
    public @Nullable String encode(@Nullable CharSequence rawPassword) {
        return String.valueOf(rawPassword.toString().hashCode());
    }

    //@Override
    public boolean matches(@Nullable CharSequence rawPassword, @Nullable String encodedPassword) {
        var passwordAsStr = String.valueOf(rawPassword.toString().hashCode());
        return encodedPassword.equals(passwordAsStr);
    }

}
