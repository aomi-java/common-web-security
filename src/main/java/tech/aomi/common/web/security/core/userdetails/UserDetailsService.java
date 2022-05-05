package tech.aomi.common.web.security.core.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Map;

/**
 * 根据用户ID查找用户
 *
 * @author Sean Create At 2020/1/3
 */
public interface UserDetailsService extends org.springframework.security.core.userdetails.UserDetailsService {

    /**
     * 加载用户信息通过ID
     *
     * @param args 其他参数
     * @return 用户信息
     * @throws UsernameNotFoundException 用户找不到异常
     */
    default UserDetails loadUser(Map<String, ?> args) throws UsernameNotFoundException {
        throw new UsernameNotFoundException("loadUser 方法未实现");
    }

    /**
     * 加载用户信息通过ID
     *
     * @param id   用户ID
     * @param args 其他参数
     * @return 用户信息
     * @throws UsernameNotFoundException 用户找不到异常
     */
    default UserDetails loadUserById(String id, Map<String, ?> args) throws UsernameNotFoundException {
        throw new UsernameNotFoundException("loadUserById 方法未实现");
    }

    @Override
    default UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        throw new UsernameNotFoundException("loadUserByUsername 方法未实现");
    }
}
