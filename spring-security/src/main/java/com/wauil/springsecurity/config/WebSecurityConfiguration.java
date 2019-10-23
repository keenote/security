/*
 * Copyright (c) 2019. dxxld@qq.com All Rights Reserved.
 */

package com.wauil.springsecurity.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collections;

/**
 * @Description: 默认路由，兜底安全规则
 * 优先级低于{@link OrderSecurityConfig}，因此会先校验{@link OrderSecurityConfig}的路径匹配规则是否与当前请求路径匹配，没匹配上才会选择当前WebSecurityConfigurerAdapter构建的filters链
 * @Author: kee
 * @Email: dxxld@qq.com
 * @Date: 2019/10/22 11:10
 * @Version: 1.0
 */
@Configuration
@Order()
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) {
        super.configure(web);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
        //默认该httpSecurity生成的filter能匹配所有的路由规则，因此如果有多个WebSecurityConfigurerAdapter需要注意路由规则和bean的顺序，把路由规则匹配范围大的放在后面
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder())
                .withUser("normal")
                .password(passwordEncoder().encode("123456"))
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("DEMO")));
    }
    @Bean
    @ConditionalOnMissingBean({BCryptPasswordEncoder.class})
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
