package thejavalistener.myfwkauth.web;

import java.util.ArrayList;
import java.util.List;

import thejavalistener.myfwkauth.OtpChannel;
import thejavalistener.myfwkauth.domain.AuthPerson;
import thejavalistener.myfwkauth.domain.AuthCredential;

public class AuthPersonDTO
{
	public int personId;
	public OtpChannel channel;
	public String destination;

	public List<AuthCredentialDTO> identities;

	public static AuthPersonDTO from(AuthPerson p, List<AuthCredential> users)
	{
		AuthPersonDTO dto = new AuthPersonDTO();

		dto.personId = p.getPersonId();

		dto.identities = new ArrayList<>();

		for(AuthCredential cred : users)
		{
			dto.identities.add(AuthCredentialDTO.from(cred));
		}

		// compatibilidad: tomar el primero
		if(!users.isEmpty())
		{
			AuthCredential cred = users.get(0);
			dto.personId = cred.getPerson().getPersonId();
			dto.channel = cred.getChannel();
			dto.destination = cred.getDestination();
		}

		return dto;
	}
}