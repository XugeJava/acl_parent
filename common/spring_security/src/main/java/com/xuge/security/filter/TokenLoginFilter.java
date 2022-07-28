package com.xuge.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xuge.base.utils.R;
import com.xuge.base.utils.ResponseUtil;
import com.xuge.security.bean.SecurityUser;
import com.xuge.security.bean.User;
import com.xuge.security.security.TokenManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * author: yjx
 * Date :2022/7/2715:09
 **/
public class TokenLoginFilter extends UsernamePasswordAuthenticationFilter {
  private AuthenticationManager authenticationManager;
  private TokenManager tokenManager;
  private RedisTemplate redisTemplate;
  public TokenLoginFilter(AuthenticationManager authenticationManager,
                          TokenManager tokenManager, RedisTemplate redisTemplate) {
    this.authenticationManager = authenticationManager;
    this.tokenManager = tokenManager;
    this.redisTemplate = redisTemplate;
    //不仅只能支持post
    this.setPostOnly(false);
    this.setRequiresAuthenticationRequestMatcher(new
            AntPathRequestMatcher("/admin/acl/login","POST"));
  }
  //1.获取表单中的用户名和密码
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    try {
      User user = new ObjectMapper().readValue(request.getInputStream(),
              User.class);
      return authenticationManager.authenticate(new
              UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), new
              ArrayList<>()));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
  //2 认证成功调用的方法
  @Override
  protected void successfulAuthentication(HttpServletRequest request,
                                          HttpServletResponse response, FilterChain chain, Authentication authResult)
          throws IOException, ServletException {
    //认证成功，得到认证成功之后用户信息
    SecurityUser user = (SecurityUser)authResult.getPrincipal();
    //根据用户名生成token
    String token = tokenManager.createToken(user.getCurrentUserInfo().getUsername());
    //把用户名称和用户权限列表放到redis
    redisTemplate.opsForValue().set(user.getCurrentUserInfo().getUsername(),user.getPermissionValueList());
    //返回token
    ResponseUtil.out(response, R.ok().data("token",token));
  }

  //3 认证失败调用的方法
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
          throws IOException, ServletException {
    ResponseUtil.out(response, R.error());
  }
}
