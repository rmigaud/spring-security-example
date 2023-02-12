package demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(request -> request
            .requestMatchers("/", "home")
            .permitAll().anyRequest().authenticated())
        .formLogin(form -> form.loginPage("/login").permitAll())
        .logout(LogoutConfigurer::permitAll).build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user =
        User.builder()
            .username("user")
            .password(new BCryptPasswordEncoder()
                .encode("password")) // this should be hashed
            .roles("USER")
            .build();

    return new InMemoryUserDetailsManager(user);
  }
}
