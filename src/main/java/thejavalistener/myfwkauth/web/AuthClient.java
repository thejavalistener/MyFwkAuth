package thejavalistener.myfwkauth.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import thejavalistener.myfwkauth.AuthException;
import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.TokenPair;
import thejavalistener.myfwkauth.XX;
import thejavalistener.myfwkauth.domain.AuthPerson;
import thejavalistener.myfwkauth.domain.AuthCredential;

public class AuthClient
{
	@Autowired
	private XX auth;

	public AuthClient(XX auth)
	{
		this.auth = auth;
	}
	
	// ================= OTP =================

	public void requestOtp(OtpChannel channel, String destination)
	{
		auth.generateOtp(channel, destination);
	}

	// ================= LOGIN =================

	public TokenPair login(OtpChannel channel, String destination, String otp) throws AuthException
	{
		return auth.login(channel, destination, otp);
	}

	// ================= REFRESH =================

	public TokenPair refresh(String refreshToken)
	{
		return auth.refresh(refreshToken);
	}

	// ================= LOGOUT =================

	public void logout(String refreshToken)
	{
		auth.logout(refreshToken);
	}

	// ================= ME =================

	public AuthPersonDTO me(String accessToken)
	{
		if(accessToken == null || accessToken.isBlank()) return null;

		AuthPerson p = auth.getPersonFromAccessToken(accessToken);
		if(p == null) return null;

		List<AuthCredential> users = auth.getCredentialsByPerson(p.getPersonId());

		return AuthPersonDTO.from(p, users);
	}	
	// ================= HELPERS =================

}
