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
@Table(name="auth_otp")
public class AuthOtp
{
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="otp_id")
	private int otpId;

    @Enumerated(EnumType.STRING)
    private OtpChannel channel;

    @Column(name="destination")
	private String destination;
    
	@Column(name="code_hash")
	private String codeHash;

	@Column(name="generated_at")
	private Timestamp generatedAt;

	@Column(name="expires_at")
	private Timestamp expiresAt;

	@Column(name="attempts")
	private int attempts;

	public int getOtpId()
	{
		return otpId;
	}

	public void setOtpId(int otpId)
	{
		this.otpId=otpId;
	}
	
	public OtpChannel getChannel()
	{
		return channel;
	}

	public void setChannel(OtpChannel channel)
	{
		this.channel=channel;
	}

	public String getCodeHash()
	{
		return codeHash;
	}

	public void setCodeHash(String codeHash)
	{
		this.codeHash=codeHash;
	}

	public Timestamp getGeneratedAt()
	{
		return generatedAt;
	}

	public void setGeneratedAt(Timestamp generatedAt)
	{
		this.generatedAt=generatedAt;
	}

	public Timestamp getExpiresAt()
	{
		return expiresAt;
	}

	public void setExpiresAt(Timestamp expiresAt)
	{
		this.expiresAt=expiresAt;
	}

	public int getAttempts()
	{
		return attempts;
	}

	public void setAttempts(int attempts)
	{
		this.attempts=attempts;
	}

	public String getDestination()
	{
		return destination;
	}

	public void setDestination(String destination)
	{
		this.destination=destination;
	}
}
