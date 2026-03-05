package thejavalistener.myfwkauth;

public interface OtpSender
{
    public void send(OtpChannel channel, String destination,String code);
}