package com.xuge.aclservice.service.impl;

import com.xuge.aclservice.entity.User;
import com.xuge.aclservice.service.PermissionService;
import com.xuge.aclservice.service.UserService;
import com.xuge.security.bean.SecurityUser;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * author: yjx
 * Date :2022/7/2716:05
 **/
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  private UserService userService;
  @Autowired
  private PermissionService permissionService;
  //根据用户名查询数据库
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    //根据用户名查询数据
    User user=userService.selectByUsername(username);

    //如果用户名为空，返回
    if(user==null){
      throw new UsernameNotFoundException("用户名找不到!");
    }
    com.xuge.security.bean.User cur = new com.xuge.security.bean.User();
    BeanUtils.copyProperties(user, cur);
    //根据用户名查询用户权限列表
    List<String> permissionList = permissionService.selectPermissionValueByUserId(user.getId());
    SecurityUser securityUser = new SecurityUser();
    //设置securityUser
    securityUser.setCurrentUserInfo(cur);
    securityUser.setPermissionValueList(permissionList);

    return securityUser;
  }
}
