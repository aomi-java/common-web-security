package tech.aomi.common.web.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import tech.aomi.common.exception.ErrorCode;

/**
 * Rest Controller 控制器异常处理控制器
 *
 * @author 田尘殇Sean(sean.snow @ live.com) createAt 2018/6/12
 */
@Slf4j
@Configuration
@ConditionalOnProperty(prefix = "aomi-tech.autoconfigure.web.exception", name = "enabled", havingValue = "true", matchIfMissing = true)
@RestControllerAdvice
public class SecurityRestControllerExceptionHandlerController {

    @ExceptionHandler({BadCredentialsException.class})
    public Result badCredentialsException(BadCredentialsException e) {
        LOGGER.error("无效的授权信息: {}", e.getMessage(), e);
        return new Result(ErrorCode.INVALID_CREDENTIAL.getCode(), e.getMessage(), null);
    }

}
