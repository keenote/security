/*
 * Copyright (c) 2019. dxxld@qq.com All Rights Reserved.
 */

package com.wauil.springsecurity.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;

/**
 * @Description: 订单模块下的安全规则,如果有多个 WebSecurityConfigurerAdapter 必须提供不同的AuthenticationManagerBuilder
 * 每个http都会生成一条单独的filter链，根据Matcher匹配路径选择使用哪一条链，建议在程序中不要使用多个 WebSecurityConfigurerAdapter ,
 * 使用不当会存在如跨域等各种问题，此处实现仅供个人测试，默认不启用
 * @Author: kee
 * @Email: dxxld@qq.com
 * @Date: 2019/10/22 16:19
 * @Version: 1.0
 */
@ConditionalOnProperty(value = "security.rule.order.enabled")
@Configuration
@Order(Ordered.LOWEST_PRECEDENCE - 1)
public class OrderSecurityConfig extends WebSecurityConfigurerAdapter {
    private final BCryptPasswordEncoder passwordEncoder;

    public OrderSecurityConfig(BCryptPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //需要自己手动创建 DefaultLoginPageGeneratingFilter 的各个属性
        //在 调用http.formLogin().loginPage(String)方法后，org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer.customLoginPage属性会变成true，
        //因此不会加载默认的DefaultLoginPageGeneratingFilter 和DefaultLogoutPageGeneratingFilter两个过滤器，默认登录和注销页面不会产生

        DefaultLoginPageGeneratingFilter orderLoginPageFilter = new DefaultLoginPageGeneratingFilter();

        orderLoginPageFilter.setFormLoginEnabled(true);
        orderLoginPageFilter.setUsernameParameter("username");
        orderLoginPageFilter.setPasswordParameter("password");
        orderLoginPageFilter.setLoginPageUrl("/order/login");
        orderLoginPageFilter.setFailureUrl("/order/login?error");
        orderLoginPageFilter.setAuthenticationUrl("/order/login");

        DefaultLogoutPageGeneratingFilter orderLogoutPageFilter = new DefaultLogoutPageGeneratingFilter();
        http.antMatcher("/order/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .addFilterAfter(orderLoginPageFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(orderLogoutPageFilter, DefaultLoginPageGeneratingFilter.class)
                .formLogin().loginPage("/order/login").and()
                .httpBasic()
        .and().csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) {
        super.configure(web);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder)
                .withUser("order")
                .password(passwordEncoder.encode("123456"))
                .roles("ORDER");

    }

}
