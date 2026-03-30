package thejavalistener.myfwkauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

//@Component
//public class AuthSecurityCfg
//{
////    @Value("${auth.security.max-login-attempts}")
////    public int maxLoginAttempts;
//
//    @Value("${auth.security.block-duration-ms}")
//    public long blockDurationMs;
//}

@Component
public class AuthSecurityCfg
{
    @Value("${auth.security.block-duration-ms:900000}")
    public long blockDurationMs;
}