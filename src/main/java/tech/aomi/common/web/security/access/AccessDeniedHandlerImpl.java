package tech.aomi.common.web.security.access;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import tech.aomi.common.exception.ErrorCode;
import tech.aomi.common.web.controller.Result;

import java.io.IOException;
import java.util.Objects;

/**
 * 403 处理器
 * 处理无权限结果
 * 仅适用于经过身份验证的用户
 *
 * @author Sean(sean.snow @ live.com) createAt 2018/7/10
 */
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {

    @Autowired
    private MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Result result = new Result(ErrorCode.ACCESS_DENIED.getCode(), accessDeniedException.getMessage());
        mappingJackson2HttpMessageConverter.write(Objects.requireNonNull(result.getBody()),
                MediaType.APPLICATION_JSON,
                new ServletServerHttpResponse(response));
    }

}
