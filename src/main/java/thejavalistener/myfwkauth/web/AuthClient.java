package thejavalistener.myfwkauth.web;

import org.springframework.beans.factory.annotation.Autowired;

import thejavalistener.myfwkauth.AuthException;
import thejavalistener.myfwkauth.AuthService;
import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.TokenPair;
import thejavalistener.myfwkauth.domain.AuthUser;

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

	public AuthUserDTO me(String accessToken)
	{
		if(accessToken == null || accessToken.isBlank()) return null;

		AuthUser u = auth.getUserFromAccessToken(accessToken);
		if(u == null) return null;

		return AuthUserDTO.from(u);
	}
	
	// ================= HELPERS =================

}
