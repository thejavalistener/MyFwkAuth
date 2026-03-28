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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.sql.Timestamp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import thejavalistener.fwkbackend.DaoSupport;
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

	private TestOtpSender otpSender;

	private AuthService auth;

	private AuthConfig config;

	private final OtpChannel CH = OtpChannel.TEST;
	private final String DEST = "test-user";

	@BeforeEach
	void setup() throws Exception
	{
		otpSender = new TestOtpSender();
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
		auth.generateOtp(CH, DEST);

		verify(dao).update(
			eq("DELETE FROM AuthOtp WHERE channel=:c AND destination=:d"),
			eq("c"), eq(CH),
			eq("d"), eq(DEST)
		);

		verify(dao).insert(any(AuthOtp.class));

		String sentOtp = otpSender.lastCode;
		assertNotNull(sentOtp);

		AuthOtp stored = new AuthOtp();
		stored.setChannel(CH);
		stored.setDestination(DEST);
		stored.setAttempts(0);
		stored.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
		stored.setCodeHash(auth._hash(sentOtp));

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("FROM AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(stored);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("FROM AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(null);

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

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(stored);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(null);

		auth.login(CH, DEST, "123456");

		verify(dao).delete(stored);
	}

	@Test
	void otp_cannotBeReused() throws Exception
	{
		AuthOtp first = new AuthOtp();
		first.setChannel(CH);
		first.setDestination(DEST);
		first.setAttempts(0);
		first.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
		first.setCodeHash(auth._hash("123456"));

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(first).thenReturn(null);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(null);

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

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(stored);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(null);

		auth.login(CH, DEST, "123456");

		verify(dao).update(anyString(), any(), any(), any(), any());
	}

	@Test
	void login_sameCredential_doesNotCreateNewPerson() throws Exception
	{
		AuthOtp otp1 = new AuthOtp();
		otp1.setChannel(CH);
		otp1.setDestination(DEST);
		otp1.setAttempts(0);
		otp1.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
		otp1.setCodeHash(auth._hash("123456"));

		AuthOtp otp2 = new AuthOtp();
		otp2.setChannel(CH);
		otp2.setDestination(DEST);
		otp2.setAttempts(0);
		otp2.setExpiresAt(new Timestamp(System.currentTimeMillis() + 100000));
		otp2.setCodeHash(auth._hash("123456"));

		AuthPerson existingPerson = new AuthPerson();
		existingPerson.setPersonId(1);

		AuthCredential existingCred = new AuthCredential();
		existingCred.setPerson(existingPerson);
		existingCred.setChannel(CH);
		existingCred.setDestination(DEST);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(otp1).thenReturn(otp2);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(null).thenReturn(existingCred);

		auth.login(CH, DEST, "123456");
		auth.login(CH, DEST, "123456");

		verify(dao, times(1)).insert(any(AuthPerson.class));
		verify(dao, times(1)).insert(any(AuthCredential.class));
	}

	@Test
	void getPersonFromAccessToken_returnsCorrectPerson()
	{
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
	void linkCredentialSuccess() throws AuthException
	{
		int personId = 1;
		String code = "123456";

		AuthOtp otp = new AuthOtp();
		otp.setCodeHash(auth._hash(code));
		otp.setExpiresAt(new Timestamp(System.currentTimeMillis() + 60000));
		otp.setAttempts(0);

		AuthPerson person = new AuthPerson();
		person.setPersonId(personId);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(otp);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(null);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthPerson")),
			any(), any()
		)).thenReturn(person);

		assertDoesNotThrow(() -> {
			auth.linkCredential(personId, OtpChannel.EMAIL, "pablo@test.com", code);
		});

		verify(dao).insert(any(AuthCredential.class));
	}

	@Test
	void linkCredential_samePerson_doesNothing() throws AuthException
	{
		int personId = 1;
		String code = "123456";

		AuthOtp otp = new AuthOtp();
		otp.setCodeHash(auth._hash(code));
		otp.setExpiresAt(new Timestamp(System.currentTimeMillis() + 60000));
		otp.setAttempts(0);

		AuthPerson person = new AuthPerson();
		person.setPersonId(personId);

		AuthCredential existing = new AuthCredential();
		existing.setPerson(person);
		existing.setChannel(OtpChannel.EMAIL);
		existing.setDestination("x@mail.com");

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(otp);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(existing);

		assertDoesNotThrow(() ->
			auth.linkCredential(personId, OtpChannel.EMAIL, "x@mail.com", code)
		);

		verify(dao, never()).insert(any(AuthCredential.class));
	}

	@Test
	void linkCredential_otherPerson_throws()
	{
		int personId = 1;
		String code = "123456";

		AuthOtp otp = new AuthOtp();
		otp.setCodeHash(auth._hash(code));
		otp.setExpiresAt(new Timestamp(System.currentTimeMillis() + 60000));
		otp.setAttempts(0);

		AuthPerson other = new AuthPerson();
		other.setPersonId(999);

		AuthCredential existing = new AuthCredential();
		existing.setPerson(other);
		existing.setChannel(OtpChannel.EMAIL);
		existing.setDestination("x@mail.com");

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(otp);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(existing);

		AuthException ex = assertThrows(
			AuthException.class,
			() -> auth.linkCredential(personId, OtpChannel.EMAIL, "x@mail.com", code)
		);

		assertEquals(AuthException.Reason.INVALID_OTP, ex.getReason());
	}

	@Test
	void linkCredential_invalidOtp_throws()
	{
		String correct = "123456";
		String wrong = "000000";

		AuthOtp otp = new AuthOtp();
		otp.setCodeHash(auth._hash(correct));
		otp.setExpiresAt(new Timestamp(System.currentTimeMillis() + 60000));
		otp.setAttempts(0);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(otp);

		AuthException ex = assertThrows(
			AuthException.class,
			() -> auth.linkCredential(1, OtpChannel.EMAIL, "a@mail.com", wrong)
		);

		assertEquals(AuthException.Reason.INVALID_OTP, ex.getReason());
		verify(dao, never()).insert(any(AuthCredential.class));
	}

	@Test
	void linkCredential_expiredOtp_throws()
	{
		String code = "123456";

		AuthOtp otp = new AuthOtp();
		otp.setCodeHash(auth._hash(code));
		otp.setExpiresAt(new Timestamp(System.currentTimeMillis() - 1000));
		otp.setAttempts(0);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("AuthOtp")),
			any(), any(), any(), any()
		)).thenReturn(otp);

		AuthException ex = assertThrows(
			AuthException.class,
			() -> auth.linkCredential(1, OtpChannel.EMAIL, "a@mail.com", code)
		);

		assertEquals(AuthException.Reason.EXPIRED_OTP, ex.getReason());
		verify(dao).delete(otp);
	}

	@Test
	void unlinkCredential_shouldSoftDeleteCredential()
	{
		int personId = 10;
		int credentialId = 20;

		AuthPerson person = new AuthPerson();
		person.setPersonId(personId);

		AuthCredential credential = new AuthCredential();
		credential.setCredentialId(credentialId);
		credential.setPerson(person);
		credential.setChannel(OtpChannel.TEST);
		credential.setDestination("user2@test.com");
		credential.setDeletedAt(null);

		when(dao.querySingleRow(
			argThat(s -> s != null && s.contains("FROM AuthCredential")),
			any(), any(), any(), any()
		)).thenReturn(credential);

		auth.unlinkCredential(personId, credentialId);

		assertNotNull(credential.getDeletedAt());
	}
}