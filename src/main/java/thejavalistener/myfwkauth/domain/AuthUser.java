package thejavalistener.myfwkauth.domain;

import java.sql.Timestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import thejavalistener.myfwkauth.OtpChannel;

@Entity
@Table(name="auth_user")
public class AuthUser
{
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private int userId;

	@Enumerated(EnumType.STRING)
	@Column(name="channel")
	private OtpChannel channel;

	@Column(name = "destination")
	private String destination;

	@Column(name = "created_at")
	private Timestamp createdAt;

	@Column(name = "deleted_at")
	private Timestamp deletedAt;

	public int getUserId()
	{
		return userId;
	}

	public void setUserId(int userId)
	{
		this.userId=userId;
	}

	public OtpChannel getChannel()
	{
		return channel;
	}

	public void setChannel(OtpChannel channel)
	{
		this.channel=channel;
	}

	public String getDestination()
	{
		return destination;
	}

	public void setDestination(String destination)
	{
		this.destination=destination;
	}

	public Timestamp getCreatedAt()
	{
		return createdAt;
	}

	public void setCreatedAt(Timestamp createdAt)
	{
		this.createdAt=createdAt;
	}

	public Timestamp getDeletedAt()
	{
		return deletedAt;
	}

	public void setDeletedAt(Timestamp deletedAt)
	{
		this.deletedAt=deletedAt;
	}
}