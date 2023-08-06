package tech.aomi.common.web.security.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import tech.aomi.common.exception.ErrorCode;
import tech.aomi.common.exception.ServiceException;
import tech.aomi.common.web.controller.Result;

import java.io.IOException;
import java.util.Objects;

/**
 * 认证异常处理
 *
 * @author 田尘殇Sean(sean.snow @ live.com) createAt 2018/7/10
 */
public class AuthenticationExceptionEntryPoint implements AuthenticationEntryPoint {

    @Autowired
    private MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException arg2) throws IOException {
        Result result;
        if (null != arg2.getCause() && arg2.getCause() instanceof ServiceException se) {
            result = Result.create(se.getErrorCode(), se.getMessage(), se.getPayload());
        } else {
            result = new Result(ErrorCode.UNAUTHORIZED.getCode(), arg2.getMessage());
        }
        mappingJackson2HttpMessageConverter.write(Objects.requireNonNull(result.getBody()), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

}
