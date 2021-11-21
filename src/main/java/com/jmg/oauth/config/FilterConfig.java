package com.jmg.oauth.config;

import com.jmg.oauth.filter.MyFilter1;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration // IOC (메모리) 등록
public class FilterConfig {
    
    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*"); // 모든 url에 필터 등록
        bean.setOrder(0); // 낮은 숫자부터 먼저 실행
        return bean;
    }
}
