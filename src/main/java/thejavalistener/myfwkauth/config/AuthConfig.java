package thejavalistener.myfwkauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuthConfig
{
    @Autowired
    public AuthOtpCfg otp;

    @Autowired
    public AuthTokenCfg token;

    @Autowired
    public AuthSecurityCfg security;
}