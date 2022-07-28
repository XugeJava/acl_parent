package com.xuge.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import javax.xml.crypto.Data;
import java.util.Date;

/**
 * author: yjx
 * Date :2022/7/2714:47
 **/
@Component
public class TokenManager {
  //token有效时长
  private long  tokenExpiration=24*60*60*1000;
  //编码秘钥
  private String tokenSignKey="123456";
  //根据用户名生成token
  public String createToken(String username){
    String token= Jwts.builder().setSubject(username).setExpiration(new Date(System.currentTimeMillis()+tokenExpiration))
            .signWith(SignatureAlgorithm.HS512,
                    tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
    return token;
  }


  //根据token字符串获取用户信息
  public String getUserByToken(String token){
    String user =
            Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
    return user;
  }
  //删除token
  public void removeToken(String token){

  }



}
