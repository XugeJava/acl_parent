package com.xuge.security.filter;

import com.xuge.security.security.TokenManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * author: yjx
 * Date :2022/7/2715:27
 **/
public class TokenAuthenticationFilter extends BasicAuthenticationFilter {
  private TokenManager tokenManager;
  private RedisTemplate redisTemplate;

  public TokenAuthenticationFilter(AuthenticationManager authenticationManager, TokenManager tokenManager, RedisTemplate redisTemplate) {
    super(authenticationManager);
    this.tokenManager = tokenManager;
    this.redisTemplate = redisTemplate;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    //获取当前认证用户权限信息
    UsernamePasswordAuthenticationToken authReq = getAuthentication(request);
    //判断，如果有权限信息，放入权限上下文中
    if (authReq != null) {
      SecurityContextHolder.getContext().setAuthentication(authReq);
    }
    chain.doFilter(request, response);
  }

  //获取当前认证用户权限信息
  private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
    //丛header中获取Token
    String token = request.getHeader("token");
    if (token != null) {
      //丛token中获取用户名
      String username = tokenManager.getUserByToken(token);
      //通过用户名从redis中获取权限列表
      List<String> permissionList = (List<String>) redisTemplate.opsForValue().get(username);
      //构建 Collection<? extends GrantedAuthority> authorities
      Collection<GrantedAuthority> authorities = new ArrayList<>();
      //遍历
      for (String permission : permissionList)    //向authorities中加入数据
      {
        //创建对象
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(permission);
        //加入到集合中
        authorities.add(simpleGrantedAuthority);
      }
      return new UsernamePasswordAuthenticationToken(username, token, authorities);
    }
    return null;
  }
}
