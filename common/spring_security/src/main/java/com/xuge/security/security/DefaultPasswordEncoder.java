package com.xuge.security.security;

import com.xuge.base.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * author: yjx
 * Date :2022/7/2714:37
 **/
@Component
public class DefaultPasswordEncoder implements PasswordEncoder {
  public DefaultPasswordEncoder() {
    this(-1);
  }
  public  DefaultPasswordEncoder(int strength){

  }
  //对字符串进行md5加密
  @Override
  public String encode(CharSequence charSequence) {
    return MD5.encrypt(charSequence.toString());
  }
  //对密码进行比对

  /**
   *
   * @param charSequence  加密前的字符
   * @param encodePwd   加密后的字符串
   * @return
   */
  @Override
  public boolean matches(CharSequence charSequence, String encodePwd) {
    return encodePwd.equals(encode(charSequence));
  }
}
