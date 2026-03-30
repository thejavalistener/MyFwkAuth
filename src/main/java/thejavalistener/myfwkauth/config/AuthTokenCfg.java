package thejavalistener.myfwkauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

//@Component
//public class AuthTokenCfg
//{
//    @Value("${auth.token.access.bytes}")
//    public int accessBytes;
//
//    // 15 minutos por defecto
//    @Value("${auth.token.access.expiration-ms:900000}")
//    public long accessExpirationMs;
//
//    @Value("${auth.token.refresh.bytes}")
//    public int refreshBytes;
//
//    // 7 días por defecto
//    @Value("${auth.token.refresh.expiration-ms:604800000}") 
//    public long refreshExpirationMs;
//}

@Component
public class AuthTokenCfg
{
    @Value("${auth.token.access.bytes:32}")
    public int accessBytes;

    @Value("${auth.token.access.expiration-ms:900000}")
    public long accessExpirationMs;

    @Value("${auth.token.refresh.bytes:32}")
    public int refreshBytes;

    @Value("${auth.token.refresh.expiration-ms:604800000}")
    public long refreshExpirationMs;
}