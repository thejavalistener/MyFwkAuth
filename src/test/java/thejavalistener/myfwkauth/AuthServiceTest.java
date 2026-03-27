package thejavalistener.myfwkauth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
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
import thejavalistener.fwkutils.various.MyReflection;
import thejavalistener.myfwkauth.config.AuthConfig;
import thejavalistener.myfwkauth.config.AuthOtpCfg;
import thejavalistener.myfwkauth.config.AuthSecurityCfg;
import thejavalistener.myfwkauth.config.AuthTokenCfg;
import thejavalistener.myfwkauth.domain.AuthCredential;
import thejavalistener.myfwkauth.domain.AuthOtp;
import thejavalistener.myfwkauth.domain.AuthPerson;
import thejavalistener.myfwkauth.domain.AuthToken;

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

        // credential no existe
        when(dao.querySingleRow(startsWith("FROM AuthCredential"), any(), any(), any(), any()))
            .thenReturn(null);

        // ===== login =====
        TokenPair pair = auth.login(CH, DEST, sentOtp);

        assertNotNull(pair);
        assertNotNull(pair.accessToken);
        assertNotNull(pair.refreshToken);

        verify(dao).insert(any(AuthPerson.class));
        verify(dao).insert(any(AuthCredential.class));
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

        AuthException ex = assertThrows(
            AuthException.class,
            () -> auth.login(CH, DEST, "000000")
        );

        assertEquals(AuthException.Reason.BLOCKED_OTP, ex.getReason());
    }
    
    @Test
    void refresh_generatesNewTokens()
    {
        AuthToken stored = new AuthToken();

        stored.setRefreshToken("REFRESH_1");
        stored.setAccessToken("ACCESS_1");

        long now = System.currentTimeMillis();

        stored.setRefreshTokenExpiresAt(new Timestamp(now + 100000));
        stored.setAccessTokenExpiresAt(new Timestamp(now + 100000));

        when(dao.querySingleRow(anyString(), any(), any()))
            .thenReturn(stored);

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
            .thenReturn(stored)
            .thenReturn(null);

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
            .thenReturn(stored)
            .thenReturn(null);

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
            .thenReturn(stored)
            .thenReturn(null);

        auth.login(CH, DEST, "123456");

        verify(dao).update(anyString(), any(), any(), any(), any());
    }
    
    @Test
    void login_sameCredential_doesNotCreateNewPerson() throws Exception
    {
        // ===== OTP válido =====
        AuthOtp otp = new AuthOtp();
        otp.setChannel(CH);
        otp.setDestination(DEST);
        otp.setAttempts(0);
        otp.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
        otp.setCodeHash(auth._hash("123456"));

        // ===== primera vez: no existe credencial =====
        when(dao.querySingleRow(startsWith("FROM AuthOtp"), any(), any(), any(), any()))
            .thenReturn(otp);

        when(dao.querySingleRow(startsWith("FROM AuthCredential"), any(), any(), any(), any()))
            .thenReturn(null); // no existe

        auth.login(CH, DEST, "123456");

        // ===== segunda vez: ya existe credencial =====
        AuthPerson existingPerson = new AuthPerson();
        existingPerson.setPersonId(1);

        AuthCredential existingCred = new AuthCredential();
        existingCred.setPerson(existingPerson);
        existingCred.setChannel(CH);
        existingCred.setDestination(DEST);

        when(dao.querySingleRow(startsWith("FROM AuthOtp"), any(), any(), any(), any()))
            .thenReturn(otp);

        when(dao.querySingleRow(startsWith("FROM AuthCredential"), any(), any(), any(), any()))
            .thenReturn(existingCred);

        auth.login(CH, DEST, "123456");

        // ===== verificaciones =====

        // persona creada SOLO una vez
        verify(dao, times(1)).insert(any(AuthPerson.class));

        // credencial creada SOLO una vez
        verify(dao, times(1)).insert(any(AuthCredential.class));
    }
    
    @Test
    void getPersonFromAccessToken_returnsCorrectPerson()
    {
        // ===== token válido =====
        AuthPerson person = new AuthPerson();
        person.setPersonId(42);

        AuthToken token = new AuthToken();
        token.setAccessToken("ACCESS_OK");
        token.setPerson(person);
        token.setAccessTokenExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));

        when(dao.querySingleRow(anyString(), any(), any()))
            .thenReturn(token);

        AuthPerson result = auth.getPersonFromAccessToken("ACCESS_OK");

        assertNotNull(result);
        assertEquals(42, result.getPersonId());
    }
    
    @Test
    void revokeAllSessions_usesPersonId() 
    {
        auth.revokeAllSessions(42);

        verify(dao).update(
            startsWith("UPDATE AuthToken "),
            eq("pid"), eq(42),
            eq("now"), any(Timestamp.class)
        );
    }

    
    @Test
    void linkCredentialSuccess() throws AuthException {
        // 1. LOS MOCKS (Los dobles de riesgo)
        dao = mock(DaoSupport.class);
        config = mock(AuthConfig.class);
        otpSender = mock(OtpSender.class);

        // 2. EL SERVICIO (Lo creamos a mano para que NO sea null nada)
        // Pasamos el otpSender por constructor y los otros por Reflection o setter
        auth = new AuthService(otpSender);
        
        // Usamos ReflectionTestUtils (o simplemente asignación si los campos son accesibles)
        // Esto asegura que 'this.dao' NO sea null dentro de AuthService
        
        MyReflection.object.setField(auth,"dao",dao);
        MyReflection.object.setField(auth,"config",config);
        
//        org.springframework.test.util.ReflectionTestUtils.setField(authService, "dao", dao);
//        org.springframework.test.util.ReflectionTestUtils.setField(authService, "config", config);

        // 3. PREPARAR ESCENARIO (Lo que queremos que pase)
        int personId = 1;
        String code = "123456";
        AuthOtp mockOtp = new AuthOtp();
        mockOtp.setCodeHash(auth._hash(code));
        mockOtp.setExpiresAt(new java.sql.Timestamp(System.currentTimeMillis() + 60000));
        
        AuthPerson mockPerson = new AuthPerson();
        mockPerson.setPersonId(personId);

        AuthOtpCfg otpCfg = new AuthOtpCfg();
        otpCfg.maxAttempts = 3;
        config.otp = otpCfg;

        // 4. CONFIGURAR RESPUESTAS (El "embocado" paso a paso)
        
        // Llamada 1: ¿Existe la credencial? -> queryMultipleRows
        // Si el HQL tiene "AuthCredential", devolvemos lista vacía
        lenient().doReturn(new java.util.ArrayList<>())
                 .when(dao).queryMultipleRows(argThat(s -> s.contains("AuthCredential")), any(Object[].class));

        // Llamada 2: Verificar OTP -> querySingleRow
        // Si el HQL tiene "AuthOtp", devolvemos el mockOtp
        lenient().doReturn(mockOtp)
                 .when(dao).querySingleRow(argThat(s -> s.contains("AuthOtp")), any(Object[].class));

        // Llamada 3: Buscar Persona -> querySingleRow
        // Si el HQL tiene "AuthPerson", devolvemos mockPerson
        lenient().doReturn(mockPerson)
                 .when(dao).querySingleRow(argThat(s -> s.contains("AuthPerson")), any(Object[].class));

        // 5. EJECUCIÓN Y VERIFICACIÓN
        assertDoesNotThrow(() -> {
            auth.linkCredential(personId, OtpChannel.EMAIL, "pablo@test.com", code);
        });

        verify(dao).insert(any(AuthCredential.class));
    }

}