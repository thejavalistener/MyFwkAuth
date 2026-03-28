package thejavalistener.myfwkauth;

public class TestOtpSender implements OtpSender
{
	public String lastCode;

	@Override
	public void send(OtpChannel channel, String destination, String code)
	{
		this.lastCode = code;
	}
}