package thejavalistener.myfwkauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.sql.Timestamp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import thejavalistener.fwkbackend.DaoSupport;
import thejavalistener.myfwkauth.config.AuthConfig;
import thejavalistener.myfwkauth.config.AuthOtpCfg;
import thejavalistener.myfwkauth.config.AuthSecurityCfg;
import thejavalistener.myfwkauth.config.AuthTokenCfg;
import thejavalistener.myfwkauth.domain.AuthOtp;
import thejavalistener.myfwkauth.domain.AuthToken;
import thejavalistener.myfwkauth.domain.AuthUser;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest
{
    @Mock
    private DaoSupport dao;

    @Mock
    private OtpSender otpSender;

    private AuthService auth;

    private AuthConfig config;

    private final OtpChannel CH = OtpChannel.TEST;
    private final String DEST = "test-user";

    @BeforeEach
    void setup() throws Exception
    {
        auth = new AuthService(otpSender);

        config = new AuthConfig();
        config.otp = new AuthOtpCfg();
        config.token = new AuthTokenCfg();
        config.security = new AuthSecurityCfg();

        config.otp.length = 6;
        config.otp.expirationMs = 60000;
        config.otp.maxAttempts = 3;
        config.otp.cooldownMs = 0;

        config.token.accessBytes = 16;
        config.token.refreshBytes = 32;
        config.token.accessExpirationMs = 60000;
        config.token.refreshExpirationMs = 120000;

        inject(auth, "dao", dao);
        inject(auth, "config", config);
    }
    
    private void inject(Object target, String field, Object value) throws Exception
    {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @Test
    void generateOtp_and_login_ok() throws Exception
    {
        // OTP no existe
        when(dao.querySingleRow(anyString(), any(), any(), any(), any()))
            .thenReturn(null);

        ArgumentCaptor<String> captor =
            ArgumentCaptor.forClass(String.class);

        // ===== generate =====
        auth.generateOtp(CH, DEST);

        verify(dao).insert(any(AuthOtp.class));
        verify(otpSender).send(eq(CH), eq(DEST), captor.capture());

        String sentOtp = captor.getValue();

        // ===== OTP almacenado =====
        AuthOtp stored = new AuthOtp();
        stored.setChannel(CH);
        stored.setDestination(DEST);
        stored.setAttempts(0);
        stored.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
        stored.setCodeHash(auth._hash(sentOtp));

        // mock query OTP
        when(dao.querySingleRow(startsWith("FROM AuthOtp"), any(), any(), any(), any()))
            .thenReturn(stored);

        // user no existe
        when(dao.querySingleRow(startsWith("FROM AuthUser"), any(), any(), any(), any()))
            .thenReturn(null);

        // ===== login =====
        TokenPair pair = auth.login(CH, DEST, sentOtp);

        assertNotNull(pair);
        assertNotNull(pair.accessToken);
        assertNotNull(pair.refreshToken);

        verify(dao).insert(any(AuthUser.class));
        verify(dao).insert(any(AuthToken.class));
    }

    @Test
    void otp_blocks_afterMaxAttempts()
    {
        AuthOtp stored = new AuthOtp();
        stored.setChannel(CH);
        stored.setDestination(DEST);
        stored.setAttempts(0);
        stored.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
        stored.setCodeHash(auth._hash("123456"));

        when(dao.querySingleRow(anyString(), any(), any(), any(), any()))
            .thenReturn(stored);

        // 3 intentos fallidos
        for(int i=0;i<config.otp.maxAttempts-1;i++)
        {
            try
            {
                auth.login(CH, DEST, "000000");
            }
            catch(AuthException e)
            {
                assertEquals(AuthException.Reason.INVALID_OTP, e.getReason());
            }
        }
        // siguiente → bloqueado
        AuthException ex = assertThrows(
            AuthException.class,
            () -> auth.login(CH, DEST, "000000")
        );

        assertEquals(AuthException.Reason.BLOCKED_OTP, ex.getReason());
    }
    
    @Test
    void refresh_generatesNewTokens()
    {
        // ===== token existente =====
        AuthToken stored = new AuthToken();

        stored.setRefreshToken("REFRESH_1");
        stored.setAccessToken("ACCESS_1");

        long now = System.currentTimeMillis();

        stored.setRefreshTokenExpiresAt(new Timestamp(now + 100000));
        stored.setAccessTokenExpiresAt(new Timestamp(now + 100000));

        // mock DAO
        when(dao.querySingleRow(anyString(), any(), any()))
            .thenReturn(stored);

        // ===== refresh =====
        TokenPair pair = auth.refresh("REFRESH_1");

        assertNotNull(pair);

        assertNotEquals("ACCESS_1", pair.accessToken);
        assertNotEquals("REFRESH_1", pair.refreshToken);
    }
    
    @Test
    void refresh_expired_returnsNull_and_revokes()
    {
        AuthToken stored = new AuthToken();

        stored.setRefreshToken("REFRESH_1");

        long now = System.currentTimeMillis();

        // expirado
        stored.setRefreshTokenExpiresAt(new Timestamp(now - 1000));

        when(dao.querySingleRow(anyString(), any(), any()))
            .thenReturn(stored);

        TokenPair pair = auth.refresh("REFRESH_1");

        assertNull(pair);
        assertNotNull(stored.getRevokedAt());
    }
    @Test
    void login_consumesOtp() throws Exception
    {
        AuthOtp stored = new AuthOtp();
        stored.setChannel(CH);
        stored.setDestination(DEST);
        stored.setAttempts(0);
        stored.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
        stored.setCodeHash(auth._hash("123456"));

        when(dao.querySingleRow(anyString(), any(), any(), any(), any()))
            .thenReturn(stored)  // OTP
            .thenReturn(null);   // USER

        auth.login(CH, DEST, "123456");

        verify(dao).delete(stored);
    }    
    
    @Test
    void otp_cannotBeReused() throws Exception
    {
        AuthOtp stored = new AuthOtp();
        stored.setChannel(CH);
        stored.setDestination(DEST);
        stored.setAttempts(0);
        stored.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
        stored.setCodeHash(auth._hash("123456"));

        when(dao.querySingleRow(anyString(), any(), any(), any(), any()))
            .thenReturn(stored)  // primer login
            .thenReturn(null);   // segundo intento (ya borrado)

        auth.login(CH, DEST, "123456");

        assertThrows(
            AuthException.class,
            () -> auth.login(CH, DEST, "123456")
        );
    }
    
    @Test
    void login_fails_whenOtpExpired()
    {
        AuthOtp stored = new AuthOtp();
        stored.setChannel(CH);
        stored.setDestination(DEST);
        stored.setAttempts(0);
        stored.setExpiresAt(new Timestamp(System.currentTimeMillis() - 1000));
        stored.setCodeHash(auth._hash("123456"));

        when(dao.querySingleRow(anyString(), any(), any(), any(), any()))
            .thenReturn(stored);

        AuthException ex = assertThrows(
            AuthException.class,
            () -> auth.login(CH, DEST, "123456")
        );

        assertEquals(AuthException.Reason.EXPIRED_OTP, ex.getReason());
        verify(dao).delete(stored);
    }
    
    @Test
    void refresh_returnsNull_whenTokenNotFound()
    {
        when(dao.querySingleRow(anyString(), any(), any()))
            .thenReturn(null);

        TokenPair pair = auth.refresh("NO_EXISTE");

        assertNull(pair);
    }
    
    @Test
    void logout_withInvalidToken_doesNothing()
    {
        when(dao.querySingleRow(anyString(), any(), any()))
            .thenReturn(null);

        auth.logout("NO_EXISTE");

        // no debe tirar excepción
    }
    
    @Test
    void login_revokesPreviousTokens() throws Exception
    {
        AuthOtp stored = new AuthOtp();
        stored.setChannel(CH);
        stored.setDestination(DEST);
        stored.setAttempts(0);
        stored.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
        stored.setCodeHash(auth._hash("123456"));

        when(dao.querySingleRow(anyString(), any(), any(), any(), any()))
            .thenReturn(stored)  // OTP
            .thenReturn(null);   // USER

        auth.login(CH, DEST, "123456");

        verify(dao).update(anyString(), any(), any(), any(), any());
    }
}