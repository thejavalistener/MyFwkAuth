package thejavalistener.myfwkauth.web;

import java.sql.Timestamp;

import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.domain.AuthUser;

public class AuthUserDTO
{
	public int userId;
	public OtpChannel channel;
	public String destination;
	public Timestamp createdAt;
	public Timestamp deletedAt;
	
	public static AuthUserDTO from(AuthUser u)
	{
		AuthUserDTO dto = new AuthUserDTO();
		dto.userId = u.getUserId();
		dto.channel = u.getChannel();
		dto.destination = u.getDestination();
		return dto;
	}
	
}
