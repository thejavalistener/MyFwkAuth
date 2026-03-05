package thejavalistener.myfwkauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import thejavalistener.fwkbackend.DaoSupport;
import thejavalistener.fwkutils.string.MyString;
import thejavalistener.fwkutils.various.MyDate;
import thejavalistener.myfwkauth.config.AuthConfig;
import thejavalistener.myfwkauth.domain.AuthOtp;
import thejavalistener.myfwkauth.domain.AuthToken;
import thejavalistener.myfwkauth.domain.AuthUser;

public class AuthFacade
{
	@Autowired
	private AuthConfig config;

	@Autowired
	private DaoSupport dao;

	private OtpSender otpSender;

	public AuthFacade(OtpSender otpSender)
	{
		this.otpSender=otpSender;
	}

	@Transactional
	public void generateOtp(OtpChannel channel, String destination)
	{
		String hql="";
		hql+="FROM AuthOtp ";
		hql+="WHERE destination=:destination ";
		hql+="  AND channel=:channel ";
		AuthOtp otp=dao.querySingleRow(hql,"destination",destination,"channel",channel);

		if(otp==null)
		{
			otp=new AuthOtp();
			otp.setDestination(destination);
			otp.setChannel(channel);
			dao.insert(otp);
		}

		otp.setAttempts(0);

		int otpCodeLen=config.otp.length;
		String code=MyString.generateRandom('0','9',otpCodeLen,otpCodeLen);
		otp.setCodeHash(_hash(code));

		long ts=System.currentTimeMillis();
		otp.setGeneratedAt(new Timestamp(ts));

		long otpExpiraEn=config.otp.expirationMs;
		otp.setExpiresAt(new Timestamp(ts+otpExpiraEn));

		// envio el OTP
		otpSender.send(channel,destination,code);
	}

	@Transactional
	public TokenPair login(OtpChannel channel, String destination, String otp) throws AuthException
	{
		_verifyOtp(channel,destination,otp); // si falla, lanza excepción

		String hql="";
		hql+="FROM AuthUser ";
		hql+="WHERE channel=:channel ";
		hql+="  AND destination=:destination ";

		AuthUser user=dao.querySingleRow(hql,"channel",channel,"destination",destination);

		if(user==null)
		{
			user=new AuthUser();
			user.setChannel(channel);
			user.setDestination(destination);
			user.setCreatedAt(new Timestamp(System.currentTimeMillis()));
			dao.insert(user);
		}
		
		hql ="UPDATE AuthToken ";
		hql+="   SET revokedAt=:now ";
		hql+="WHERE user.userId=:id ";
		hql+="  AND revokedAt IS NULL ";
		dao.update(hql,"id",user.getUserId(),"now",new Timestamp(System.currentTimeMillis()));

		AuthToken t=new AuthToken();
		t.setUser(user);

		int lenRefresh=config.token.refreshBytes;
		int lenAccess=config.token.accessBytes;

		t.setAccessToken(_generateToken(lenAccess));
		t.setRefreshToken(_generateToken(lenRefresh));

		long now=System.currentTimeMillis();
		Timestamp nowTs=new Timestamp(now);

		t.setAccessTokenIssuedAt(nowTs);
		t.setRefreshTokenIssuedAt(nowTs);

		long refreshExpMs=config.token.refreshExpirationMs;
		long accessExpMs=config.token.accessExpirationMs;

		t.setAccessTokenExpiresAt(new Timestamp(now+accessExpMs));
		t.setRefreshTokenExpiresAt(new Timestamp(now+refreshExpMs));

		dao.insert(t);

		TokenPair pair=new TokenPair();
		pair.accessToken=t.getAccessToken();
		pair.refreshToken=t.getRefreshToken();

		return pair;
	}

	private void _verifyOtp(OtpChannel channel, String destination, String otp) throws AuthException
	{
		String hql="";
		hql+="FROM AuthOtp ";
		hql+="WHERE channel=:channel ";
		hql+="  AND destination=:destination ";

		AuthOtp o=dao.querySingleRow(hql,"channel",channel,"destination",destination);

		if(o==null) throw new AuthException(AuthException.Reason.INVALID_OTP);

		long now=System.currentTimeMillis();

		if(now>o.getExpiresAt().getTime())
		{
			dao.delete(o);
			throw new AuthException(AuthException.Reason.EXPIRED_OTP);
		}

		if(!o.getCodeHash().equals(_hash(otp)))
		{
			o.setAttempts(o.getAttempts()+1);

			if(o.getAttempts()>=config.security.maxLoginAttempts)
			{
				dao.delete(o);
				throw new AuthException(AuthException.Reason.BLOCKED_OTP);
			}

			throw new AuthException(AuthException.Reason.INVALID_OTP);
		}

		dao.delete(o);
	}

	@Transactional(readOnly=true)
	public AuthUser getUserFromAccessToken(String accessToken)
	{
		String hql="";
		hql+="FROM AuthToken ";
		hql+="WHERE accessToken=:at ";
		hql+="AND revokedAt IS NULL ";
		AuthToken t=dao.querySingleRow(hql,"at",accessToken);

		if(t==null) return null;

		long now=System.currentTimeMillis();

		if(t.getAccessTokenExpiresAt()==null||now>t.getAccessTokenExpiresAt().getTime()) return null;

		return t.getUser();
	}

	@Transactional(readOnly=true)
	public Integer getUserIdFromAccessToken(String accessToken)
	{
		AuthUser u=getUserFromAccessToken(accessToken);
		return u!=null?u.getUserId():null;
	}

	@Transactional
	public TokenPair refresh(String refreshToken)
	{
		String hql="";
		hql+="FROM AuthToken ";
		hql+="WHERE refreshToken=:rt ";
		hql+="  AND revokedAt IS NULL ";
		AuthToken t=dao.querySingleRow(hql,"rt",refreshToken);

		if(t==null) return null;

		long now=System.currentTimeMillis();

		// Refresh expirado => revocar sesión
		if(t.getRefreshTokenExpiresAt()==null||now>t.getRefreshTokenExpiresAt().getTime())
		{
			t.setRevokedAt(new Timestamp(now));
			return null;
		}

		// Rotación obligatoria: nuevo refresh token
		int lenRefresh=config.token.refreshBytes;
		t.setRefreshToken(_generateToken(lenRefresh));
		t.setRefreshTokenIssuedAt(new Timestamp(now));

		long refreshExpMs=config.token.refreshExpirationMs;
		t.setRefreshTokenExpiresAt(new MyDate(now).addMillis(refreshExpMs).toSqlTimestamp());

		// Nuevo access token
		int lenAccess=config.token.accessBytes;
		t.setAccessToken(_generateToken(lenAccess));
		t.setAccessTokenIssuedAt(new Timestamp(now));

		long accessExpMs=config.token.accessExpirationMs;
		t.setAccessTokenExpiresAt(new MyDate(now).addMillis(accessExpMs).toSqlTimestamp());

		TokenPair pair=new TokenPair();
		pair.accessToken=t.getAccessToken();
		pair.refreshToken=t.getRefreshToken();
		return pair;
	}

	@Transactional
	public void logout(String refreshToken)
	{
		String hql="";
		hql+="FROM AuthToken ";
		hql+="WHERE refreshToken=:rt ";
		hql+="  AND revokedAt IS NULL ";
		AuthToken t=dao.querySingleRow(hql,"rt",refreshToken);

		if(t!=null)
		{
			t.setRevokedAt(new Timestamp(System.currentTimeMillis()));
		}
	}

	@Transactional
	public void revokeAllSessions(int userId)
	{
		String hql="";
		hql+="UPDATE AuthToken ";
		hql+="   SET revokedAt=:now ";
		hql+="WHERE user.userId=:uid ";
		hql+="  AND revokedAt IS NULL ";
		dao.update(hql,"uid",userId,"now",new Timestamp(System.currentTimeMillis()));
	}

	private static final SecureRandom RNG=new SecureRandom();

	private String _generateToken(int bytesLen)
	{
		byte[] bytes=new byte[bytesLen];
		RNG.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	public String _hash(String s)
	{
		if(s==null) return null;

		try
		{
			MessageDigest md=MessageDigest.getInstance("SHA-256");
			byte[] digest=md.digest(s.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}
		catch(NoSuchAlgorithmException e)
		{
			throw new RuntimeException(e);
		}
	}
}