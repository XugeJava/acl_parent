package com.xuge.security.security;

import com.xuge.base.utils.R;
import com.xuge.base.utils.ResponseUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * author: yjx
 * Date :2022/7/2714:58
 **/
public class TokenLogoutHandler implements LogoutHandler {
  private TokenManager tokenManager;
  private RedisTemplate redisTemplate;
  //构造器
  public TokenLogoutHandler(TokenManager tokenManager, RedisTemplate redisTemplate) {
    this.tokenManager = tokenManager;
    this.redisTemplate = redisTemplate;
  }

  @Override
  public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
    //1.丛header获取token
    //2.token不为空,移除token，丛redis删除token
    String token=httpServletRequest.getHeader("token");
    if(token!=null){
      //移除
      tokenManager.removeToken(token);
      //从token中获取用户名
      String username=tokenManager.getUserByToken(token);
      //redis删除
      redisTemplate.delete(username);
    }
    ResponseUtil.out(httpServletResponse, R.ok());
  }
}
