package thejavalistener.myfwkauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AuthTokenCfg
{
    @Value("${auth.token.access.bytes}")
    public int accessBytes;

    @Value("${auth.token.access.expiration-ms}")
    public long accessExpirationMs;

    @Value("${auth.token.refresh.bytes}")
    public int refreshBytes;

    @Value("${auth.token.refresh.expiration-ms}")
    public long refreshExpirationMs;
}