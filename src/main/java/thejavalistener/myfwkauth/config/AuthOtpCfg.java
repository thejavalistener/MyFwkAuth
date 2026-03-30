package thejavalistener.myfwkauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

//@Component
//public class AuthOtpCfg
//{
//    @Value("${auth.otp.length:6}")
//    public int length;
//
//    @Value("${auth.otp.expiration-ms}")
//    public long expirationMs;
//
//    @Value("${auth.otp.max-attempts}")
//    public int maxAttempts;
//
//    @Value("${auth.otp.cooldown-ms}")
//    public long cooldownMs;
//}

@Component
public class AuthOtpCfg
{
    @Value("${auth.otp.length:6}")
    public int length;

    @Value("${auth.otp.expiration-ms:300000}")
    public long expirationMs;

    @Value("${auth.otp.max-attempts:5}")
    public int maxAttempts;

    @Value("${auth.otp.cooldown-ms:60000}")
    public long cooldownMs;
}