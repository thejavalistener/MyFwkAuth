package thejavalistener.myfwkauth.domain;

import java.sql.Timestamp;

import thejavalistener.myfwkauth.OtpChannel;

public class AuthUserDTO
{
	public int userId;
	public OtpChannel channel;
	public String destination;
	public Timestamp createdAt;
	public Timestamp deletedAt;
}
