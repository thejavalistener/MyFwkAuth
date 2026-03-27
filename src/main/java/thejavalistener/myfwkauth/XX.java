package thejavalistener.myfwkauth;

import java.util.List;

import thejavalistener.myfwkauth.domain.AuthCredential;
import thejavalistener.myfwkauth.domain.AuthPerson;

public interface XX
{
	// === DOMINIO: OTP ===
	public void otpGenerate(OtpChannel channel, String destination);

	// === DOMINIO: AUTH (Sesión y Tokens) ===
	public TokenPair authLogin(OtpChannel channel, String destination, String otp) throws AuthException;

	public void authLogout(String refreshToken);

	public TokenPair authSessionRefresh(String refreshToken);

	// === DOMINIO: PERSON (Identidad y Vínculos) ===
	public AuthPerson personGetByAccessToken(String accessToken);

	public List<AuthCredential> personGetCredentials(int personId);

	public void personLinkCredential(int personId, OtpChannel channel, String destination, String otp) throws AuthException;

	public void personRevokeSessions(int personId); // "All" es redundante si el método
}