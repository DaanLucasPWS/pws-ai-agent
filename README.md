# SocrAItes prototype

Lokale Streamlit-interface voor de PWS-agent. Dit is de versie die we voor het PWS gebruiken. Alle programmeerbestanden staan in deze map (`AI-agent code`).

Deze versie bevat:

- meerdere chats;
- bestandsbijlagen per chat;
- een bestandsbibliotheek met mappen;
- uploaden van PDF, Word, PowerPoint, tekst en afbeeldingen;
- lokale opslag in `app_data/`.
- AI-antwoorden via de OpenAI API met context uit chatbijlagen;
- aanpasbare agentinstructies in `agent_prompt.txt`.
- actuele informatie via de ingebouwde webzoekfunctie;
- een eerste PowerPoint-bewerkingsmodus die tekstwijzigingen als nieuwe downloadbare presentatie opslaat.
- permanente gebruikersopslag via Supabase wanneer `SUPABASE_URL` en `SUPABASE_SECRET_KEY` zijn ingesteld;

## Starten

```powershell
cd "AI-agent code"
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

De AI gebruikt de sleutel uit de omgevingsvariabele `OPENAI_API_KEY`. Pas de instructies aan in `agent_prompt.txt`; de app leest dit bestand bij iedere vraag opnieuw in. Voeg geen leerlinggegevens toe.

## Gebruikersscheiding voor hosting

Wanneer `LESMAAT_USERS_JSON` als servergeheim is ingesteld, verschijnt een loginpagina. Iedere ingelogde gebruiker krijgt een eigen map onder `app_data/users/<gebruikersnaam>/` met een eigen `state.json` en bestandsbibliotheek. Zonder deze variabele blijft de app in lokale ontwikkelmodus met de bestaande `app_data/`.

Maak lokaal een gebruikersrecord met:

```powershell
python create_user_record.py docent1
```

Zet de uitgegeven JSON-record daarna in het servergeheim `LESMAAT_USERS_JSON`. Combineer meerdere records in één JSON-object. Zet wachtwoorden en `OPENAI_API_KEY` nooit in GitHub of in gewone bronbestanden.

## Hostingchecklist

- `OPENAI_API_KEY` als servergeheim instellen;
- `LESMAAT_USERS_JSON` als servergeheim instellen;
- `requirements.txt` volledig laten installeren;
- controleren dat ook `matplotlib`, `numpy` en `sympy` op de server beschikbaar zijn voor grafieken;
- permanente opslag instellen voor `app_data/users/`, of een externe opslag/database gebruiken;
- testen met minstens twee accounts of chats en bestanden volledig gescheiden blijven;
- controleren dat Word- en PDF-bestanden met grafieken correct worden gegenereerd.

De permanente opslag gebruikt de tabel `user_states` en de private Storage-bucket `lesmaat-files`. Maak deze aan met het SQL-script dat tijdens de hostinginrichting is besproken. Zonder geldige Supabase Secrets blijft de lokale ontwikkelmodus actief.
