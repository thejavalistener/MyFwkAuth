package thejavalistener.myfwkauth.domain;

import java.sql.Timestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name="auth_token")
public class AuthToken
{
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "token_id")
	private int tokenId;

	@ManyToOne
	@JoinColumn(name = "user_id")
	private AuthUser user;

	@Column(name = "access_token")
	private String accessToken;

	@Column(name = "refresh_token")
	private String refreshToken;

	@Column(name = "access_token_issued_at")
	private Timestamp accessTokenIssuedAt;

	@Column(name = "access_token_expires_at")
	private Timestamp accessTokenExpiresAt;

	@Column(name = "refresh_token_issued_at")
	private Timestamp refreshTokenIssuedAt;

	@Column(name = "refresh_token_expires_at")
	private Timestamp refreshTokenExpiresAt;

	@Column(name = "revoked_at")
	private Timestamp revokedAt;

	public int getTokenId()
	{
		return tokenId;
	}

	public void setTokenId(int tokenId)
	{
		this.tokenId=tokenId;
	}

	public AuthUser getUser()
	{
		return user;
	}

	public void setUser(AuthUser user)
	{
		this.user=user;
	}

	public String getAccessToken()
	{
		return accessToken;
	}

	public void setAccessToken(String accessToken)
	{
		this.accessToken=accessToken;
	}

	public String getRefreshToken()
	{
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken)
	{
		this.refreshToken=refreshToken;
	}

	public Timestamp getAccessTokenIssuedAt()
	{
		return accessTokenIssuedAt;
	}

	public void setAccessTokenIssuedAt(Timestamp accessTokenIssuedAt)
	{
		this.accessTokenIssuedAt=accessTokenIssuedAt;
	}

	public Timestamp getAccessTokenExpiresAt()
	{
		return accessTokenExpiresAt;
	}

	public void setAccessTokenExpiresAt(Timestamp accessTokenExpiresAt)
	{
		this.accessTokenExpiresAt=accessTokenExpiresAt;
	}

	public Timestamp getRefreshTokenIssuedAt()
	{
		return refreshTokenIssuedAt;
	}

	public void setRefreshTokenIssuedAt(Timestamp refreshTokenIssuedAt)
	{
		this.refreshTokenIssuedAt=refreshTokenIssuedAt;
	}

	public Timestamp getRefreshTokenExpiresAt()
	{
		return refreshTokenExpiresAt;
	}

	public void setRefreshTokenExpiresAt(Timestamp refreshTokenExpiresAt)
	{
		this.refreshTokenExpiresAt=refreshTokenExpiresAt;
	}

	public Timestamp getRevokedAt()
	{
		return revokedAt;
	}

	public void setRevokedAt(Timestamp revokedAt)
	{
		this.revokedAt=revokedAt;
	}
}
