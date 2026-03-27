package thejavalistener.myfwkauth.web;

import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.domain.AuthCredential;

public class AuthCredentialDTO
{
	public OtpChannel channel;
	public String destination;

	public static AuthCredentialDTO from(AuthCredential u)
	{
		AuthCredentialDTO dto = new AuthCredentialDTO();
		dto.channel = u.getChannel();
		dto.destination = u.getDestination();
		return dto;
	}
}