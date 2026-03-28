package thejavalistener.myfwkauth.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import thejavalistener.myfwkauth.AuthException;
import thejavalistener.myfwkauth.AuthService;
import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.TokenPair;
import thejavalistener.myfwkauth.domain.AuthCredential;
import thejavalistener.myfwkauth.domain.AuthPerson;

@RestController
@RequestMapping("/auth")
public class AuthController
{
	@Autowired
	private AuthService auth;
	
	@PostMapping("/otp")
	public ResponseEntity<Void> requestOtp(@RequestBody OtpRequest req)
	{
		auth.otpGenerate(req.channel, req.destination);
		return ResponseEntity.ok().build();
	}

	@PostMapping("/login")
	public ResponseEntity<TokenPair> login(@RequestBody LoginRequest req) throws AuthException
	{
		TokenPair pair = auth.sessionLogin(req.channel, req.destination, req.otp);
		return ResponseEntity.ok(pair);
	}

	@PostMapping("/refresh")
	public ResponseEntity<TokenPair> refresh(@RequestBody RefreshRequest req)
	{
		TokenPair pair = auth.sessionRefresh(req.refreshToken);
		if(pair == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		return ResponseEntity.ok(pair);
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(@RequestBody LogoutRequest req)
	{
		auth.sessionLogout(req.refreshToken);
		return ResponseEntity.ok().build();
	}

	@GetMapping("/me")
	public ResponseEntity<AuthPersonDTO> me(@RequestHeader(value="Authorization", required=false) String authHeader)
	{
		String accessToken = _extractBearer(authHeader);
		if(accessToken == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

		AuthPerson p = auth.personGetByAccessToken(accessToken);
		if(p == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

		List<AuthCredential> users = auth.personGetCredentials(p.getPersonId());

		return ResponseEntity.ok(AuthPersonDTO.from(p, users));
	}
	
	@ExceptionHandler(AuthException.class)
	public ResponseEntity<AuthError> onAuthException(AuthException ex)
	{
		AuthError err = new AuthError();
		err.reason = ex.getReason() != null ? ex.getReason().name() : "AUTH_ERROR";
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(err);
	}

	private String _extractBearer(String header)
	{
		if(header == null) return null;
		String h = header.trim();
		if(h.length() < 8) return null;
		if(!h.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
		String token = h.substring(7).trim();
		return token.isEmpty() ? null : token;
	}

	// ================= DTOs =================

	public static class OtpRequest
	{
		public OtpChannel channel;
		public String destination;
	}

	public static class LoginRequest
	{
		public OtpChannel channel;
		public String destination;
		public String otp;
	}

	public static class RefreshRequest
	{
		public String refreshToken;
	}

	public static class LogoutRequest
	{
		public String refreshToken;
	}

	public static class AuthError
	{
		public String reason;
	}
}