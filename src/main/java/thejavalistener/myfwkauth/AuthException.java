package thejavalistener.myfwkauth;

public class AuthException extends Exception
{
    public enum Reason { INVALID_OTP, EXPIRED_OTP, BLOCKED_OTP, INVALID_TOKEN, EXPIRED_TOKEN }

    private final Reason reason;

    public AuthException(Reason reason) { super(reason.name()); this.reason = reason; }

    public Reason getReason() { return reason; }
}