package thejavalistener.myfwkauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import thejavalistener.fwkbackend.DaoSupport;
import thejavalistener.fwkutils.string.MyString;
import thejavalistener.fwkutils.various.MyDate;
import thejavalistener.myfwkauth.config.AuthConfig;
import thejavalistener.myfwkauth.domain.AuthCredential;
import thejavalistener.myfwkauth.domain.AuthOtp;
import thejavalistener.myfwkauth.domain.AuthPerson;
import thejavalistener.myfwkauth.domain.AuthToken;

public class AuthService
{
	@Autowired
	private AuthConfig config;

	@Autowired
	private DaoSupport dao;

	private OtpSender otpSender;

	public AuthService(OtpSender otpSender)
	{
		this.otpSender = otpSender;
	}

	// ================= OTP =================

//	@Transactional
//	public void generateOtp(OtpChannel channel, String destination)
//	{
//		String hql="";
//		hql+="FROM AuthOtp ";
//		hql+="WHERE destination=:destination ";
//		hql+="  AND channel=:channel ";
//
//		AuthOtp otp=dao.querySingleRow(hql,"destination",destination,"channel",channel);
//
//		if(otp==null)
//		{
//			otp=new AuthOtp();
//			otp.setDestination(destination);
//			otp.setChannel(channel);
//			dao.insert(otp);
//		}
//
//		otp.setAttempts(0);
//
//		int otpCodeLen=config.otp.length;
//		String code=MyString.generateRandom('0','9',otpCodeLen,otpCodeLen);
//		otp.setCodeHash(_hash(code));
//
//		long ts=System.currentTimeMillis();
//		otp.setGeneratedAt(new Timestamp(ts));
//		otp.setExpiresAt(new Timestamp(ts+config.otp.expirationMs));
//
//		otpSender.send(channel,destination,code);
//	}

	@Transactional
	public void generateOtp(OtpChannel channel, String destination)
	{
		// borrar OTP previo
		dao.update(
			"DELETE FROM AuthOtp WHERE channel=:c AND destination=:d",
			"c", channel,
			"d", destination
		);

		// crear nuevo OTP directamente
		AuthOtp otp = new AuthOtp();
		otp.setDestination(destination);
		otp.setChannel(channel);
		otp.setAttempts(0);

		int otpCodeLen = config.otp.length;
		String code = MyString.generateRandom('0','9',otpCodeLen,otpCodeLen);
		otp.setCodeHash(_hash(code));

		long ts = System.currentTimeMillis();
		otp.setGeneratedAt(new Timestamp(ts));
		otp.setExpiresAt(new Timestamp(ts + config.otp.expirationMs));

		dao.insert(otp);

		otpSender.send(channel, destination, code);
	}
	
	// ================= LOGIN =================

	@Transactional
	public TokenPair login(OtpChannel channel, String destination, String otp) throws AuthException
	{
		_verifyOtp(channel,destination,otp);

		String hql="";
		hql+="FROM AuthCredential ";
		hql+="WHERE channel=:channel ";
		hql+="  AND destination=:destination ";

		AuthCredential cred=dao.querySingleRow(hql,"channel",channel,"destination",destination);

		AuthPerson person;

		if(cred==null)
		{
			person=new AuthPerson();
			person.setCreatedAt(new Timestamp(System.currentTimeMillis()));
			dao.insert(person);

			cred=new AuthCredential();
			cred.setChannel(channel);
			cred.setDestination(destination);
			cred.setCreatedAt(new Timestamp(System.currentTimeMillis()));
			cred.setPerson(person);
			dao.insert(cred);
		}
		else
		{
			person=cred.getPerson();
		}

		// revoke sesiones anteriores
		hql="";
		hql+="UPDATE AuthToken ";
		hql+="   SET revokedAt=:now ";
		hql+="WHERE person.personId=:pid ";
		hql+="  AND revokedAt IS NULL ";

		dao.update(hql,"pid",person.getPersonId(),"now",new Timestamp(System.currentTimeMillis()));

		// crear nuevo token
		AuthToken t=new AuthToken();
		t.setPerson(person);

		int lenAccess=config.token.accessBytes;
		int lenRefresh=config.token.refreshBytes;

		t.setAccessToken(_generateToken(lenAccess));
		t.setRefreshToken(_generateToken(lenRefresh));

		long now=System.currentTimeMillis();
		Timestamp nowTs=new Timestamp(now);

		t.setAccessTokenIssuedAt(nowTs);
		t.setRefreshTokenIssuedAt(nowTs);

		t.setAccessTokenExpiresAt(new Timestamp(now+config.token.accessExpirationMs));
		t.setRefreshTokenExpiresAt(new Timestamp(now+config.token.refreshExpirationMs));

		dao.insert(t);

		TokenPair pair=new TokenPair();
		pair.accessToken=t.getAccessToken();
		pair.refreshToken=t.getRefreshToken();

		return pair;
	}

	// ================= TOKEN =================

	private AuthToken _getValidToken(String accessToken)
	{
		String hql="";
		hql+="FROM AuthToken ";
		hql+="WHERE accessToken=:at ";
		hql+="AND revokedAt IS NULL ";

		AuthToken t=dao.querySingleRow(hql,"at",accessToken);

		if(t==null) return null;

		long now=System.currentTimeMillis();

		if(t.getAccessTokenExpiresAt()==null || now>t.getAccessTokenExpiresAt().getTime())
			return null;

		return t;
	}

	@Transactional(readOnly=true)
	public AuthPerson getPersonFromAccessToken(String accessToken)
	{
		AuthToken t=_getValidToken(accessToken);
		return t!=null ? t.getPerson() : null;
	}

	@Transactional(readOnly=true)
	public List<AuthCredential> getCredentialsByPerson(int personId)
	{
		String hql="";
		hql+="FROM AuthCredential ";
		hql+="WHERE person.personId=:pid ";

		return dao.queryMultipleRows(hql,"pid",personId);
	}

	// ================= OTP VERIFY =================

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

			if(o.getAttempts()>=config.otp.maxAttempts)
			{
				dao.delete(o);
				throw new AuthException(AuthException.Reason.BLOCKED_OTP);
			}

			throw new AuthException(AuthException.Reason.INVALID_OTP);
		}

		dao.delete(o);
	}

	
	// ================= REFRESH =================

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

		if(t.getRefreshTokenExpiresAt()==null || now>t.getRefreshTokenExpiresAt().getTime())
		{
			t.setRevokedAt(new Timestamp(now));
			return null;
		}

		int lenRefresh=config.token.refreshBytes;
		int lenAccess=config.token.accessBytes;

		t.setRefreshToken(_generateToken(lenRefresh));
		t.setRefreshTokenIssuedAt(new Timestamp(now));
		t.setRefreshTokenExpiresAt(new MyDate(now).addMillis(config.token.refreshExpirationMs).toSqlTimestamp());

		t.setAccessToken(_generateToken(lenAccess));
		t.setAccessTokenIssuedAt(new Timestamp(now));
		t.setAccessTokenExpiresAt(new MyDate(now).addMillis(config.token.accessExpirationMs).toSqlTimestamp());

		TokenPair pair=new TokenPair();
		pair.accessToken=t.getAccessToken();
		pair.refreshToken=t.getRefreshToken();

		return pair;
	}

	// ================= LOGOUT =================

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
	public void revokeAllSessions(int personId)
	{
		String hql="";
		hql+="UPDATE AuthToken ";
		hql+="   SET revokedAt=:now ";
		hql+="WHERE person.personId=:pid ";
		hql+="  AND revokedAt IS NULL ";

		dao.update(hql,"pid",personId,"now",new Timestamp(System.currentTimeMillis()));
	}

//	@Transactional
//	public void linkCredential(int personId, OtpChannel channel, String destination, String otp) throws AuthException
//	{
//		// validar OTP
//		_verifyOtp(channel, destination, otp);
//
//		// evitar duplicados
//		String hql="";
//		hql+="FROM AuthCredential ";
//		hql+="WHERE channel=:channel ";
//		hql+="  AND destination=:destination ";
//
//		AuthCredential existing = dao.querySingleRow(hql, "channel", channel, "destination", destination);
//
//		if(existing != null)
//		{
//			// ya existe → no hacer nada o lanzar excepción si querés
//			return;
//		}
//
//		// buscar persona
//		AuthPerson p = dao.find(AuthPerson.class, personId);
//		if(p == null) return;
//
//		// crear credencial
//		AuthCredential cred = new AuthCredential();
//		cred.setChannel(channel);
//		cred.setDestination(destination);
//		cred.setCreatedAt(new Timestamp(System.currentTimeMillis()));
//		cred.setPerson(p);
//
//		dao.insert(cred);
//	}


	@Transactional
	public void linkCredential(int personId, OtpChannel channel, String destination, String otp) throws AuthException
	{
		_verifyOtp(channel, destination, otp);

		String hql = "";
		hql += "FROM AuthCredential ";
		hql += "WHERE channel=:channel ";
		hql += "  AND destination=:destination ";

		AuthCredential existing = dao.querySingleRow(hql, "channel", channel, "destination", destination);

		if(existing != null)
		{
			if(existing.getPerson() != null && existing.getPerson().getPersonId() == personId) return;
			throw new AuthException(AuthException.Reason.INVALID_OTP);
		}

		
		hql = "";
		hql += "FROM AuthPerson ";
		hql += "WHERE personId=:pid ";

		AuthPerson person = dao.querySingleRow(hql, "pid", personId);
		if(person == null) return;

		AuthCredential cred = new AuthCredential();
		cred.setPerson(person);
		cred.setChannel(channel);
		cred.setDestination(destination);
		cred.setCreatedAt(new Timestamp(System.currentTimeMillis()));
		dao.insert(cred);
	}
	
	// ================= UTILS =================

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