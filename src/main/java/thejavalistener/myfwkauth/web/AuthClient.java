package thejavalistener.myfwkauth.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import thejavalistener.myfwkauth.AuthException;
import thejavalistener.myfwkauth.AuthService;
import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.TokenPair;
import thejavalistener.myfwkauth.domain.AuthCredential;
import thejavalistener.myfwkauth.domain.AuthPerson;

public class AuthClient
{
	@Autowired
	private AuthService auth;

	public AuthClient(AuthService auth)
	{
		this.auth = auth;
	}
	
	// ================= OTP =================

	public void requestOtp(OtpChannel channel, String destination)
	{
		auth.otpGenerate(channel, destination);
	}

	// ================= LOGIN =================

	public TokenPair login(OtpChannel channel, String destination, String otp) throws AuthException
	{
		return auth.sessionLogin(channel, destination, otp);
	}

	// ================= REFRESH =================

	public TokenPair refresh(String refreshToken)
	{
		return auth.sessionRefresh(refreshToken);
	}

	// ================= LOGOUT =================

	public void logout(String refreshToken)
	{
		auth.sessionLogout(refreshToken);
	}

	// ================= ME =================

	public AuthPersonDTO me(String accessToken)
	{
		if(accessToken == null || accessToken.isBlank()) return null;

		AuthPerson p = auth.personGetByAccessToken(accessToken);
		if(p == null) return null;

		List<AuthCredential> users = auth.personGetCredentials(p.getPersonId());

		return AuthPersonDTO.from(p, users);
	}	
	// ================= HELPERS =================

}
