//package thejavalistener.myfwkauth;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.junit.jupiter.api.Assertions.assertNotEquals;
//import static org.junit.jupiter.api.Assertions.assertNotNull;
//import static org.junit.jupiter.api.Assertions.assertNull;
//import static org.junit.jupiter.api.Assertions.assertThrows;
//import static org.mockito.ArgumentMatchers.anyString;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.mockito.Mockito.times;
//import static org.mockito.Mockito.verify;
//
//import org.junit.jupiter.api.Test;
//import org.mockito.ArgumentCaptor;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.test.context.ActiveProfiles;
//import org.springframework.transaction.annotation.Transactional;
//
//import thejavalistener.fwkbackend.DaoSupport;
//import thejavalistener.myfwkauth.config.AuthConfig;
//import thejavalistener.myfwkauth.domain.AuthOtp;
//import thejavalistener.myfwkauth.domain.AuthUser;
//
//@ActiveProfiles("test")
//@Transactional
//@SpringBootTest
//public class AuthFacadeTest
//{
//    @Autowired
//    private AuthFacade auth;
//
//    @Autowired
//    private DaoSupport dao;
//
//    @Autowired
//    private AuthConfig config;
//
//    @MockBean
//    private OtpSender otpSender;
//
//    private static final OtpChannel CH = OtpChannel.TEST;
//    private static final String DEST = "test-user";
//    
//    @Test
//    void generateOtp_createsOtp_andSendsIt()
//    {
//        auth.generateOtp(CH, DEST);
//
//        String hql="";
//        hql+="FROM AuthOtp ";
//        hql+="WHERE channel=:c ";
//        hql+="  AND destination=:d ";
//
//        AuthOtp otp=dao.querySingleRow(hql,"c",CH,"d",DEST);
//
//        assertNotNull(otp);
//        assertEquals(0,otp.getAttempts());
//        assertNotNull(otp.getCodeHash());
//
//        verify(otpSender,times(1))
//            .send(eq(CH),eq(DEST),anyString());
//    }
//    
//    @Test
//    void generateOtp_resetsAttempts()
//    {
//        auth.generateOtp(CH,DEST);
//
//        AuthOtp otp=dao.querySingleRow(
//            "FROM AuthOtp WHERE channel=:c AND destination=:d",
//            "c",CH,"d",DEST);
//
//        otp.setAttempts(3);
//
//        auth.generateOtp(CH,DEST);
//
//        AuthOtp otp2=dao.querySingleRow(
//            "FROM AuthOtp WHERE channel=:c AND destination=:d",
//            "c",CH,"d",DEST);
//
//        assertEquals(0,otp2.getAttempts());
//    }
//    
//    @Test
//    void login_createsUser_andTokens() throws Exception
//    {
//        auth.generateOtp(CH,DEST);
//
//        ArgumentCaptor<String> captor=
//            ArgumentCaptor.forClass(String.class);
//
//        verify(otpSender).send(eq(CH),eq(DEST),captor.capture());
//
//        String otp=captor.getValue();
//
//        TokenPair pair=auth.login(CH,DEST,otp);
//
//        assertNotNull(pair);
//        assertNotNull(pair.accessToken);
//        assertNotNull(pair.refreshToken);
//
//        AuthUser user=dao.querySingleRow(
//            "FROM AuthUser WHERE destination=:d",
//            "d",DEST);
//
//        assertNotNull(user);
//    }
//    
//    @Test
//    void login_fails_withInvalidOtp()
//    {
//        auth.generateOtp(CH,DEST);
//
//        assertThrows(
//            AuthException.class,
//            () -> auth.login(CH,DEST,"999999")
//        );
//    }
//    
//    @Test
//    void otp_blocks_afterMaxAttempts()
//    {
//        auth.generateOtp(CH,DEST);
//
//        int max=config.getOtp().getMaxAttempts();
//
//        for(int i=0;i<max;i++)
//        {
//            try
//            {
//                auth.login(CH,DEST,"000000");
//            }
//            catch(AuthException ignored){}
//        }
//
//        assertThrows(
//            AuthException.class,
//            () -> auth.login(CH,DEST,"000000")
//        );
//    }
//    
//    @Test
//    void getUserFromAccessToken_returnsUser() throws Exception
//    {
//        auth.generateOtp(CH,DEST);
//
//        ArgumentCaptor<String> captor=
//            ArgumentCaptor.forClass(String.class);
//
//        verify(otpSender).send(eq(CH),eq(DEST),captor.capture());
//
//        String otp=captor.getValue();
//
//        TokenPair pair=auth.login(CH,DEST,otp);
//
//        AuthUser u=auth.getUserFromAccessToken(pair.accessToken);
//
//        assertNotNull(u);
//        assertEquals(DEST,u.getDestination());
//    }
//    
//    @Test
//    void refresh_generatesNewTokens() throws Exception
//    {
//        auth.generateOtp(CH,DEST);
//
//        ArgumentCaptor<String> captor=
//            ArgumentCaptor.forClass(String.class);
//
//        verify(otpSender).send(eq(CH),eq(DEST),captor.capture());
//
//        String otp=captor.getValue();
//
//        TokenPair pair=auth.login(CH,DEST,otp);
//
//        TokenPair newPair=auth.refresh(pair.refreshToken);
//
//        assertNotNull(newPair);
//
//        assertNotEquals(pair.accessToken,newPair.accessToken);
//        assertNotEquals(pair.refreshToken,newPair.refreshToken);
//    }
//    
//    @Test
//    void logout_revokesSession() throws Exception
//    {
//        auth.generateOtp(CH,DEST);
//
//        ArgumentCaptor<String> captor=
//            ArgumentCaptor.forClass(String.class);
//
//        verify(otpSender).send(eq(CH),eq(DEST),captor.capture());
//
//        String otp=captor.getValue();
//
//        TokenPair pair=auth.login(CH,DEST,otp);
//
//        auth.logout(pair.refreshToken);
//
//        AuthUser u=auth.getUserFromAccessToken(pair.accessToken);
//
//        assertNull(u);
//    }
//    
//    @Test
//    void revokeAllSessions_invalidatesTokens() throws Exception
//    {
//        auth.generateOtp(CH,DEST);
//
//        ArgumentCaptor<String> captor=
//            ArgumentCaptor.forClass(String.class);
//
//        verify(otpSender).send(eq(CH),eq(DEST),captor.capture());
//
//        String otp=captor.getValue();
//
//        TokenPair pair=auth.login(CH,DEST,otp);
//
//        AuthUser user=auth.getUserFromAccessToken(pair.accessToken);
//
//        auth.revokeAllSessions(user.getUserId());
//
//        AuthUser u=auth.getUserFromAccessToken(pair.accessToken);
//
//        assertNull(u);
//    }
//    
//    
//    
//    
//}
